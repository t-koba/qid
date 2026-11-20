//! Test-only live MIT proof. Run through scripts/kerberos/test-mit-spnego.py,
//! which owns the realm, credentials, process-group deadline and cleanup.
//! Ordinary workspace tests report this proof as ignored, never as passed.
//!
//! The happy path drives a real KDC-issued ticket through qid_federation's
//! production HTTP login route end to end: ticket acceptance, Negotiate reply,
//! JIT local-subject resolution and audit. The refusal cases call the same
//! production acceptor directly. Every ticket uses the production loader,
//! options and single-step validation sequence; this fixture never builds
//! krb5 keytabs or accept options itself.

use axum::{
    body::Body,
    http::{Method, Request, StatusCode, header::AUTHORIZATION, header::WWW_AUTHENTICATE},
};
use base64::prelude::{BASE64_STANDARD, Engine};
use http_body_util::BodyExt;
use qid_core::{
    cache::MemoryCache,
    state::SharedState,
    tenant::{RealmId, TenantId},
    test_helpers,
};
use qid_crypto::LocalSigner;
use qid_federation::{
    federation_routes,
    kerberos_acceptor::{
        AcceptedNegotiate, KerberosAcceptError, KerberosKeytab, accept_with_options,
        build_accept_options,
    },
};
use qid_storage::{
    AuditRepository, CiamRepository, FileRepository, RealmRepository, UserRepository,
};
use std::{
    io::{self, Read, Write},
    path::{Path, PathBuf},
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
    sync::Arc,
    time::Duration,
};
use tower::ServiceExt;

const SERVICE: &str = "HTTP/acceptor.qid.test@QID.MIT.TEST";
const WRONG_SERVICE: &str = "HTTP/other.qid.test@QID.MIT.TEST";
const EXPIRED_SERVICE: &str = "HTTP/expired.qid.test@QID.MIT.TEST";
const CLIENT: &str = "client@QID.MIT.TEST";
const REALM: &str = "QID.MIT.TEST";
const MAX_TOKEN: usize = 1024 * 1024; // Fixture IPC budget, not a protocol limit.

struct MitPeer {
    child: Child,
    input: ChildStdin,
    output: ChildStdout,
}

impl MitPeer {
    fn new(target: &str) -> io::Result<Self> {
        let python = std::env::var_os("QID_MIT_PYTHON")
            .ok_or_else(|| io::Error::other("run the MIT fixture script"))?;
        let mut child = Command::new(python)
            .arg(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../scripts/kerberos/mit-initiator.py"
            ))
            .arg(target)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;
        match (child.stdin.take(), child.stdout.take()) {
            (Some(input), Some(output)) => Ok(Self {
                child,
                input,
                output,
            }),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                Err(io::Error::other("MIT pipes unavailable"))
            }
        }
    }

    fn receive(&mut self) -> io::Result<(bool, Vec<u8>)> {
        let mut header = [0; 5];
        self.output.read_exact(&mut header)?;
        assert!(header[0] <= 1, "invalid MIT completion status");
        let size = u32::from_be_bytes([header[1], header[2], header[3], header[4]]) as usize;
        assert!(size <= MAX_TOKEN, "MIT frame exceeds fixture budget");
        let mut token = vec![0; size];
        self.output.read_exact(&mut token)?;
        Ok((header[0] == 1, token))
    }

    fn send(&mut self, token: &[u8]) -> io::Result<()> {
        assert!(!token.is_empty() && token.len() <= MAX_TOKEN);
        self.input.write_all(&(token.len() as u32).to_be_bytes())?;
        self.input.write_all(token)?;
        self.input.flush()
    }

    fn initial(&mut self) -> io::Result<Vec<u8>> {
        let (complete, token) = self.receive()?;
        assert!(!complete, "MIT must wait for mutual authentication/AP-REP");
        assert!(!token.is_empty(), "MIT must produce an initial token");
        Ok(token)
    }
}

impl Drop for MitPeer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Isolated store for the route's JIT user, identity link and audit events.
struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> io::Result<Self> {
        let path = std::env::temp_dir().join(format!("qid-mit-route-{}", ulid::Ulid::new()));
        std::fs::create_dir(&path)?;
        Ok(Self(path))
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The production contract is category-level: ticket crypto, time, replay and
/// service checks all surface as `NegotiationFailed` with no identity. A check
/// that was dropped and let the ticket through would show as `Ok`, so an `Err`
/// here still proves the acceptor refused the token; only the underlying krb5
/// error distinction is intentionally no longer observable.
fn assert_refused(label: &str, result: Result<AcceptedNegotiate, KerberosAcceptError>) {
    assert_eq!(
        result.err(),
        Some(KerberosAcceptError::NegotiationFailed),
        "{label}"
    );
}

#[tokio::test]
#[ignore = "requires disposable MIT realm; run scripts/kerberos/test-mit-spnego.py"]
async fn mit_spnego_acceptor_proof() -> io::Result<()> {
    let keytab_path = std::env::var_os("QID_MIT_KEYTAB").expect("run the MIT fixture script");
    let keytab = KerberosKeytab::load(Path::new(&keytab_path))
        .unwrap_or_else(|_| panic!("load fixture service keytab"));
    // The route reads state.shared_cache for replay; the direct acceptor cases
    // below must share the very same store to prove the route consumed the token.
    let cache = Arc::new(MemoryCache::new());
    let mut mit = MitPeer::new(SERVICE)?;
    let original = mit.initial()?;

    // Happy path: the KDC-issued token goes through the production HTTP route,
    // not through a direct acceptor call.
    let directory = TestDirectory::new()?;
    let repo = Arc::new(
        FileRepository::new(directory.0.join("store.json").to_str().unwrap())
            .await
            .unwrap(),
    );
    repo.migrate().await.unwrap();
    let realm = RealmId::from("test");
    repo.create_realm(
        &TenantId::from("tenant-1"),
        &realm,
        "https://id.example.com",
        Some("Test Realm"),
    )
    .await
    .unwrap();

    let mut config = test_helpers::test_config();
    let federation = &mut config.realms[0].protocols.federation;
    federation.enabled = true;
    federation.inbound_providers = serde_json::from_value(serde_json::json!([{
        "id": "corp-kerberos",
        "kind": "kerberos_spnego",
        "issuer": "https://id.example.com/kerberos",
        "enabled": true,
        "jit_provisioning": true,
        "account_linking": true,
        "claim_mappings": [
            { "source": "principal", "target": "display_name", "required": false }
        ],
        "kerberos_spnego": {
            "realm": REALM,
            "service_principal": SERVICE,
            "keytab_path": keytab_path.to_str().expect("fixture keytab path"),
        }
    }]))
    .unwrap();
    let state = Arc::new(
        SharedState::new(
            config,
            Arc::clone(&repo),
            Arc::new(LocalSigner::from_secret(
                "mit-spnego-route-proof",
                b"test-secret",
            )),
            serde_json::json!({}),
        )
        .unwrap()
        .with_shared_cache(cache.clone()),
    );
    let app = federation_routes::<FileRepository>().with_state(state);

    let authorization = format!("Negotiate {}", BASE64_STANDARD.encode(&original));
    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/federation/test/spnego/negotiate")
                .header(AUTHORIZATION, authorization)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let headers = response.headers().clone();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["status"], "linked");
    assert_eq!(json["provider"], "corp-kerberos");
    assert_eq!(json["provider_kind"], "kerberos_spnego");
    let local_user_id = json["local_user_id"].as_str().expect("local user id");

    // The HTTP response carries the acceptor's AP-REP back to the independent
    // MIT initiator, which verifies it before reporting mutual completion.
    let challenge = headers
        .get(WWW_AUTHENTICATE)
        .expect("mutual-auth reply header")
        .to_str()
        .unwrap();
    let encoded = challenge
        .strip_prefix("Negotiate ")
        .expect("Negotiate scheme");
    let reply = BASE64_STANDARD.decode(encoded).expect("base64 AP-REP");
    assert!(!reply.is_empty(), "HTTP reply must carry the AP-REP");
    mit.send(&reply)?;
    let (complete, next) = mit.receive()?;
    assert!(
        complete && next.is_empty(),
        "MIT did not verify the mutual handshake/AP-REP from the HTTP route"
    );

    // The route resolved a local subject and recorded the JIT audit trail.
    let user = repo
        .get_user_by_id(local_user_id)
        .await
        .unwrap()
        .expect("JIT local user");
    assert_eq!(user.realm_id, realm.as_str());
    // The principal claim mapped to display_name proves which identity the
    // route discovered from the KDC-issued ticket.
    assert_eq!(user.display_name.as_deref(), Some(CLIENT));
    let link = repo
        .get_ciam_identity_link_by_external_subject(&realm, "corp-kerberos", CLIENT)
        .await
        .unwrap()
        .expect("identity link for the MIT principal");
    assert_eq!(link.user_id, local_user_id);
    let audit = repo.list_audit_events(Some(&realm), 50).await.unwrap();
    for action in [
        "federation.jit_account_created",
        "federation.ciam_identity_link_stored",
    ] {
        assert!(
            audit
                .iter()
                .any(|event| event.action == action && event.target_id == local_user_id),
            "missing {action} audit event for the local subject"
        );
    }
    assert!(mit.child.wait().expect("reap MIT initiator").success());

    // A fresh acceptor with the same injected cache must reject the exact token
    // that the HTTP route just accepted.
    assert_refused(
        "exact initial token must be refused as a replay",
        accept_with_options(
            &keytab,
            SERVICE,
            REALM,
            build_accept_options(cache.clone()),
            &original,
        ),
    );

    // Mutate a token already proven valid above, not an unrelated fixture.
    // MIT's optimistic token ends with the encrypted authenticator. Flip its
    // final checksum byte, leaving DER lengths untouched.
    let mut damaged = original.clone();
    *damaged.last_mut().expect("nonempty MIT token") ^= 1;
    assert_refused(
        "tampered MIT token must fail cryptographic verification",
        accept_with_options(
            &keytab,
            SERVICE,
            REALM,
            build_accept_options(cache.clone()),
            &damaged,
        ),
    );

    // The other principal exists in the MIT realm, so this is a genuine
    // KDC-issued ticket, not an unknown-service failure at the initiator.
    // Only the intended service's key is exported to the acceptor keytab.
    let mut other = MitPeer::new(WRONG_SERVICE)?;
    let wrong_token = other.initial()?;
    assert_refused(
        "real ticket for another service must not be accepted",
        accept_with_options(
            &keytab,
            SERVICE,
            REALM,
            build_accept_options(cache.clone()),
            &wrong_token,
        ),
    );

    // MIT issues this separate service a ten-second ticket. With zero test
    // skew, a real KDC-issued token delayed past endtime must fail at
    // ticket-time validation. Only this request overrides the production
    // default skew; every other case keeps it.
    let expired_keytab_path =
        std::env::var_os("QID_MIT_EXPIRED_KEYTAB").expect("run the MIT fixture script");
    let expired_keytab = KerberosKeytab::load(Path::new(&expired_keytab_path))
        .unwrap_or_else(|_| panic!("load fixture expired-service keytab"));
    let mut expired_peer = MitPeer::new(EXPIRED_SERVICE)?;
    let expired_token = expired_peer.initial()?;
    std::thread::sleep(Duration::from_secs(12));
    let mut options = build_accept_options(cache.clone());
    options.max_skew_secs = 0;
    assert_refused(
        "expired MIT ticket must fail at ticket-time validation",
        accept_with_options(
            &expired_keytab,
            EXPIRED_SERVICE,
            REALM,
            options,
            &expired_token,
        ),
    );
    Ok(())
}
