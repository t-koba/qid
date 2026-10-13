use qid_policy::{CedarPolicyEngine, Decision, PolicyContext, PolicyEngine, RegoPolicyEngine};
use tokio::io::AsyncWriteExt;

/// Serve one canned HTTP response per connection on loopback and return the
/// base URL. The adapters under test speak plain HTTP to 127.0.0.1.
async fn fixture(status: &'static str, body: &'static str) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            use tokio::io::AsyncReadExt;
            let _ = stream.read(&mut buf).await;
            let response = format!(
                "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes()).await;
        }
    });
    format!("http://{addr}")
}

fn ctx() -> PolicyContext {
    PolicyContext {
        subject_id: Some("alice".to_string()),
        ..PolicyContext::default()
    }
}

const ALLOW_BODY: &str = r#"{"result":{"allow":true,"policy_id":"fixture-allow"}}"#;
const DENY_BODY: &str = r#"{"result":{"allow":false,"policy_id":"fixture-deny"}}"#;

#[tokio::test]
async fn rego_accepts_200_allow_and_deny() {
    let allow = RegoPolicyEngine::new(fixture("200 OK", ALLOW_BODY).await, "qid/decision");
    let details = allow.decide(&ctx()).await;
    assert_eq!(details.decision, Decision::Allow);
    assert_eq!(details.policy_id, "fixture-allow");

    let deny = RegoPolicyEngine::new(fixture("200 OK", DENY_BODY).await, "qid/decision");
    let details = deny.decide(&ctx()).await;
    assert_eq!(details.decision, Decision::Deny);
}

#[tokio::test]
async fn rego_denies_error_status_with_allow_shaped_body() {
    for status in ["500 Internal Server Error", "400 Bad Request"] {
        let engine = RegoPolicyEngine::new(fixture(status, ALLOW_BODY).await, "qid/decision");
        let details = engine.decide(&ctx()).await;
        assert_eq!(details.decision, Decision::Deny, "status {status}");
        assert_eq!(details.policy_id, "opa-error");
        assert!(details.policy_tags.contains(&"qid:opa:error".to_string()));
    }
}

#[tokio::test]
async fn rego_denies_malformed_200_body() {
    let engine = RegoPolicyEngine::new(fixture("200 OK", "not json").await, "qid/decision");
    assert_eq!(engine.decide(&ctx()).await.decision, Decision::Deny);
}

#[tokio::test]
async fn cedar_accepts_200_allow_and_deny() {
    let allow = CedarPolicyEngine::new(fixture("200 OK", ALLOW_BODY).await, "qid/decision");
    let details = allow.decide(&ctx()).await;
    assert_eq!(details.decision, Decision::Allow);
    assert_eq!(details.policy_id, "fixture-allow");

    let deny = CedarPolicyEngine::new(fixture("200 OK", DENY_BODY).await, "qid/decision");
    let details = deny.decide(&ctx()).await;
    assert_eq!(details.decision, Decision::Deny);
}

#[tokio::test]
async fn cedar_denies_error_status_with_allow_shaped_body() {
    for status in ["500 Internal Server Error", "400 Bad Request"] {
        let engine = CedarPolicyEngine::new(fixture(status, ALLOW_BODY).await, "qid/decision");
        let details = engine.decide(&ctx()).await;
        assert_eq!(details.decision, Decision::Deny, "status {status}");
        assert_eq!(details.policy_id, "cedar-error");
        assert!(details.policy_tags.contains(&"qid:cedar:error".to_string()));
    }
}

#[tokio::test]
async fn cedar_denies_malformed_200_body() {
    let engine = CedarPolicyEngine::new(fixture("200 OK", "not json").await, "qid/decision");
    assert_eq!(engine.decide(&ctx()).await.decision, Decision::Deny);
}
