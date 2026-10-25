//! Password-push factor operations; protocol context belongs to the caller.
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use qid_core::{
    error::{QidError, QidResult},
    models::{PushDecision, PushLoginChallenge, PushPurpose},
    notification::{NotificationChannel, NotificationRequest},
    plan::RuntimeRealm,
    state::SharedState,
    util::{now_seconds, sha256_hex},
};
use qid_storage::prelude::*;
use rand::RngCore;
use serde::Deserialize;

pub(crate) fn invalid() -> QidError {
    QidError::Unauthorized {
        message: "push authentication is not available".into(),
    }
}
pub(crate) fn secret() -> String {
    let mut bytes = [0; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}
/// Recheck deployment policy on issuance, device decision and browser completion.
pub fn available<'a, R: Repository>(
    state: &'a SharedState<R>,
    realm: &str,
) -> QidResult<&'a RuntimeRealm> {
    let realm = state.require_realm(realm)?;
    let secure_base = url::Url::parse(&state.config.server.public_base_url).is_ok_and(|url| {
        url.scheme() == "https"
            && url.host_str().is_some()
            && url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none()
    });
    if !realm.mfa.push.enabled
        || !realm.accepts_password_authentication()
        || !secure_base
        || state.config.server.notification.is_none()
        || state.notification_transport.is_none()
    {
        return Err(invalid());
    }
    Ok(realm)
}
/// Holding this value retains a delivery slot. Nonces live only until delivery.
pub struct PendingDelivery {
    pub challenge: PushLoginChallenge,
    delivery: NotificationRequest,
    _permit: tokio::sync::OwnedSemaphorePermit,
}
/// Call only after server-side password verification. The caller owns a browser
/// binding domain; it must never accept a verifier supplied in a client request.
pub async fn prepare<R: Repository>(
    state: &SharedState<R>,
    realm_id: &str,
    user_id: &str,
    browser_binding_verifier: String,
) -> QidResult<PendingDelivery> {
    let realm = available(state, realm_id)?;
    let policy = &realm.mfa.push;
    let notification = state
        .config
        .server
        .notification
        .as_ref()
        .ok_or_else(invalid)?;
    let _permit = state
        .notification_delivery_slots
        .clone()
        .try_acquire_owned()
        .map_err(|_| invalid())?;
    let authenticator = state
        .repo
        .list_push_authenticators(&realm_id.into(), user_id)
        .await?
        .into_iter()
        .find(|a| a.revoked_at.is_none())
        .ok_or_else(invalid)?;
    if authenticator.destination.is_empty()
        || authenticator.destination.len() > policy.max_destination_bytes
    {
        return Err(invalid());
    }
    let now = now_seconds();
    let nonce = secret();
    let challenge = PushLoginChallenge {
        id: secret(),
        realm_id: realm_id.to_string(),
        user_id: user_id.to_string(),
        authenticator_id: authenticator.id.clone(),
        purpose: PushPurpose::PasswordLogin,
        nonce_verifier: sha256_hex(nonce.as_bytes()),
        browser_binding_verifier,
        resend_admitted_at: Vec::new(),
        created_at: now,
        expires_at: now + policy.ttl_seconds,
        max_attempts: policy.max_attempts,
        attempt_count: 0,
        decision: None,
        decided_at: None,
        consumed_at: None,
    };
    // Admission happens before retaining protocol state or calling the provider.
    if !state
        .repo
        .try_issue_push_login(
            &challenge,
            policy.max_issuances_per_window,
            policy.issuance_window_seconds,
        )
        .await?
    {
        return Err(invalid());
    }
    let delivery = notification_request(
        &challenge,
        nonce,
        authenticator.destination,
        notification.provider.clone(),
    );
    Ok(PendingDelivery {
        challenge,
        delivery,
        _permit,
    })
}
impl PendingDelivery {
    /// Delivery acceptance does not change approval state.
    pub async fn send<R: Repository>(
        self,
        state: &SharedState<R>,
    ) -> QidResult<PushLoginChallenge> {
        let notification = state
            .config
            .server
            .notification
            .as_ref()
            .ok_or_else(invalid)?;
        let transport = state.notification_transport.as_ref().ok_or_else(invalid)?;
        let sent = tokio::time::timeout(
            std::time::Duration::from_secs(notification.timeout_seconds),
            transport.send(self.delivery),
        )
        .await;
        if !matches!(sent, Ok(Ok(ref response)) if response.sent) {
            return Err(invalid());
        }
        Ok(self.challenge)
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionRequest {
    realm_id: String,
    user_id: String,
    challenge_id: String,
    nonce: String,
    decision: PushDecision,
    proof: String,
}

/// Path realm binding before any signature attempt is spent.
pub async fn record_decision_in_realm<R: Repository>(
    state: &SharedState<R>,
    realm: &str,
    req: DecisionRequest,
) -> QidResult<()> {
    if req.realm_id != realm {
        return Err(invalid());
    }
    record_decision(state, req).await
}
pub async fn record_decision<R: Repository>(
    state: &SharedState<R>,
    req: DecisionRequest,
) -> QidResult<()> {
    let policy = &available(state, &req.realm_id)?.mfa.push;
    let c = state
        .repo
        .get_push_login(
            &req.realm_id.clone().into(),
            &req.user_id,
            &req.challenge_id,
        )
        .await?
        .ok_or_else(invalid)?;
    let a = state
        .repo
        .get_push_authenticator(
            &req.realm_id.clone().into(),
            &req.user_id,
            &c.authenticator_id,
        )
        .await?
        .ok_or_else(invalid)?;
    let proof = if req.proof.len() <= policy.max_proof_bytes.div_ceil(3) * 4 {
        URL_SAFE_NO_PAD.decode(&req.proof).ok()
    } else {
        None
    };
    let verified = proof.as_deref().is_some_and(|proof| {
        proof.len() <= policy.max_proof_bytes
            && qid_mfa::push::verify_login(&c, &a, &req.nonce, req.decision, proof).is_ok()
    });
    let accepted = state
        .repo
        .attempt_push_login(&c, verified.then_some(req.decision), now_seconds())
        .await?;
    if !accepted || !verified {
        return Err(invalid());
    }
    Ok(())
}

/// Storage atomically rechecks registration, expiry, owner/transaction/browser
/// binding, decision and one-use status. No read-then-write approval authority.
pub async fn complete_password<R: Repository>(
    state: &SharedState<R>,
    challenge: &PushLoginChallenge,
    browser_verifier: &str,
) -> QidResult<crate::auth::AuthResult> {
    available(state, &challenge.realm_id)?;
    let user = state
        .repo
        .get_user_by_id(&challenge.user_id)
        .await?
        .filter(|u| u.realm_id == challenge.realm_id)
        .ok_or_else(invalid)?;
    if !state
        .repo
        .redeem_push_login(challenge, browser_verifier, now_seconds())
        .await?
    {
        return Err(invalid());
    }
    Ok(crate::auth::AuthResult {
        user,
        acr: "urn:qid:acr:password".into(),
        amr: vec!["pwd".into(), "push".into()],
        session_id: None,
    })
}

/// Display context only: this number never enters proof verification or approval.
pub fn transaction_number(challenge: &PushLoginChallenge) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(challenge.id.as_bytes());
    let first = u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]);
    format!("{:06}", first % 1_000_000)
}
fn notification_request(
    c: &PushLoginChallenge,
    nonce: String,
    recipient: String,
    provider: String,
) -> NotificationRequest {
    NotificationRequest {
        channel: NotificationChannel::Push, provider, recipient,
        subject: Some("Approve sign-in".into()),
        body: "Compare the transaction number with your browser before approving on your registered device.".into(),
        template_id: None,
        data_json: serde_json::json!({"realm_id": c.realm_id, "user_id": c.user_id,
            "challenge_id": c.id, "authenticator_id": c.authenticator_id, "purpose": "password_login",
            "nonce": nonce, "expires_at": c.expires_at, "transaction_number": transaction_number(c)}),
    }
}
/// Reserve and rotate durably before provider I/O. Never refund a failed send.
pub async fn resend<R: Repository>(
    state: &SharedState<R>,
    realm_id: &str,
    user_id: &str,
    challenge_id: &str,
    browser_verifier: &str,
) -> QidResult<PushLoginChallenge> {
    let policy = &available(state, realm_id)?.mfa.push;
    let notification = state
        .config
        .server
        .notification
        .as_ref()
        .ok_or_else(invalid)?;
    let permit = state
        .notification_delivery_slots
        .clone()
        .try_acquire_owned()
        .map_err(|_| invalid())?;
    let c = state
        .repo
        .get_push_login(&realm_id.into(), user_id, challenge_id)
        .await?
        .ok_or_else(invalid)?;
    if !qid_core::util::constant_time_eq(
        c.browser_binding_verifier.as_bytes(),
        browser_verifier.as_bytes(),
    ) {
        return Err(invalid());
    }
    let a = state
        .repo
        .get_push_authenticator(&realm_id.into(), user_id, &c.authenticator_id)
        .await?
        .ok_or_else(invalid)?;
    if a.destination.is_empty() || a.destination.len() > policy.max_destination_bytes {
        return Err(invalid());
    }
    let nonce = secret();
    let challenge = state
        .repo
        .try_resend_push_login(
            &c,
            browser_verifier,
            &sha256_hex(nonce.as_bytes()),
            policy.max_issuances_per_window,
            policy.issuance_window_seconds,
            policy.resend_cooldown_seconds,
        )
        .await?
        .ok_or_else(invalid)?;
    let delivery = notification_request(
        &challenge,
        nonce,
        a.destination,
        notification.provider.clone(),
    );
    PendingDelivery {
        challenge,
        delivery,
        _permit: permit,
    }
    .send(state)
    .await
}
