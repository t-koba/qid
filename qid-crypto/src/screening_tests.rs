use super::*;
use qid_core::{config::PasswordConfig, models::PasswordCredential, state::PasswordCredentials};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

fn config() -> PasswordScreeningConfig {
    serde_json::from_value(serde_json::json!({"range_url":"https://range.example/range/"})).unwrap()
}

// Only this private fixture replaces the validated HTTPS URL with loopback HTTP.
// It retains the production client, timeout, redirect and streaming code.
async fn fixture(
    response: Vec<u8>,
    delay_ms: u64,
    timeout_ms: u64,
    max_bytes: usize,
) -> (PasswordScreening, tokio::task::JoinHandle<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (mut stream, request) = tokio::time::timeout(Duration::from_secs(2), async {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut byte = [0; 1];
            while !request.ends_with(b"\r\n\r\n") {
                stream.read_exact(&mut byte).await.unwrap();
                request.push(byte[0]);
            }
            (stream, request)
        })
        .await
        .expect("bounded loopback request");
        if delay_ms > 0 {
            // Send headers immediately, then stall a valid body: timeout must cover chunks.
            let split = response
                .windows(4)
                .position(|bytes| bytes == b"\r\n\r\n")
                .unwrap()
                + 4;
            stream.write_all(&response[..split]).await.unwrap();
            tokio::time::sleep(Duration::from_millis(delay_ms)).await;
            let _ = stream.write_all(&response[split..]).await;
        } else {
            let _ = stream.write_all(&response).await;
        }
        String::from_utf8(request).unwrap()
    });
    let mut cfg = config();
    cfg.timeout_ms = timeout_ms;
    cfg.max_response_bytes = max_bytes;
    let mut screening = PasswordScreening::new(&cfg).unwrap();
    screening.range.as_mut().unwrap().1 = format!("http://{address}/range/").parse().unwrap();
    (screening, task)
}

fn response(body: impl AsRef<[u8]>) -> Vec<u8> {
    let body = body.as_ref();
    let mut wire = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    wire.extend_from_slice(body);
    wire
}

#[tokio::test]
async fn range_positive_survives_invalid_utf8_under_allow_policy() {
    let password = "candidate";
    let digest = hex::encode_upper(sha1::Sha1::digest(password.as_bytes()));
    let positive = format!("{}:1\r\n", &digest[5..]);
    for body in [
        [positive.as_bytes(), b"\xff"].concat(),
        [b"\xff\n", positive.as_bytes()].concat(),
    ] {
        let (mut screening, task) = fixture(response(body), 0, 1000, 1024).await;
        screening.on_unavailable = ScreeningUnavailable::Allow;
        assert_eq!(screening.check(password).await, Err(not_allowed()));
        assert!(task.await.unwrap().starts_with("GET /range/"));
    }
}

#[test]
fn range_parser_preserves_line_and_count_validation() {
    let suffix = "a".repeat(35);
    for ending in ["", "\n", "\r\n"] {
        for count in ["0", "000", "18446744073709551615"] {
            let body = format!("{}:{count}{ending}", "B".repeat(35));
            assert_eq!(parse_range(body.as_bytes(), &suffix), Ok(false));
        }
    }
    for body in [
        Vec::new(),
        b"\n".to_vec(),
        b"\xff".to_vec(),
        format!("{suffix}:0\r").into_bytes(),
        format!("{suffix}:0\n\n").into_bytes(),
        [format!("{suffix}:0\n").as_bytes(), b"\xff"].concat(),
        format!("{}:1", "A".repeat(34)).into_bytes(),
        format!("{}:1", "G".repeat(35)).into_bytes(),
        format!("{suffix}:").into_bytes(),
        format!("{suffix}:+1").into_bytes(),
        format!("{suffix}:1:2").into_bytes(),
        format!("{suffix}:18446744073709551616").into_bytes(),
    ] {
        assert_eq!(parse_range(&body, &suffix), Err(()), "{body:?}");
    }
}

#[tokio::test]
async fn local_screening_uses_exact_utf8_bytes_and_never_changes_hash_or_verify() {
    let password = " é\n";
    let mut cfg = PasswordConfig::default();
    cfg.argon2id.memory_kib = 8;
    cfg.argon2id.time_cost = 1;
    cfg.screening = Some(
        serde_json::from_value(serde_json::json!({
            "sha256_hex":[hex::encode(Sha256::digest(password.as_bytes()))]
        }))
        .unwrap(),
    );
    let owner = crate::CredentialContext::resolve(&cfg).unwrap();
    assert_eq!(owner.prepare(password).await.unwrap_err(), not_allowed());
    for different in ["é", " e\u{301}\n", " é", " É\n"] {
        assert!(owner.prepare(different).await.is_ok());
    }
    // Low-level hashing/verification remains available for an already verified password.
    let credential = PasswordCredential {
        user_id: "u".into(),
        hash: owner.hash(password).unwrap(),
        algorithm: crate::ARGON2ID_ALGORITHM.into(),
    };
    assert_eq!(owner.verify(password, &credential), (true, false));
    cfg.screening = None;
    assert!(
        crate::CredentialContext::resolve(&cfg)
            .unwrap()
            .prepare(password)
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn range_sends_only_prefix_and_padding_header_and_compares_suffix_locally() {
    let password = "test-password";
    let digest = hex::encode_upper(sha1::Sha1::digest(password.as_bytes()));
    for (body, expected) in [
        (
            format!(
                "{}:19\r\n{}:0\r\n",
                digest[5..].to_ascii_lowercase(),
                "0".repeat(35)
            ),
            Err(not_allowed()),
        ),
        (
            format!("{}:0\r\n{}:2\r\n", &digest[5..], "0".repeat(35)),
            Ok(()),
        ),
        (
            format!("invalid\r\n{}:1\r\n", &digest[5..]),
            Err(not_allowed()),
        ),
    ] {
        let (mut screening, task) = fixture(response(&body), 0, 1000, 1024).await;
        if body.starts_with("invalid") {
            screening.on_unavailable = ScreeningUnavailable::Allow;
        }
        assert_eq!(screening.check(password).await, expected);
        let request = task.await.unwrap();
        let lower = request.to_ascii_lowercase();
        assert!(request.starts_with(&format!("GET /range/{} HTTP/1.1\r\n", &digest[..5])));
        assert!(lower.contains("add-padding: true\r\n"));
        assert!(request.ends_with("\r\n\r\n"));
        assert!(!request.contains(password));
        assert!(!lower.contains(&digest[5..].to_ascii_lowercase()));
    }
}

#[tokio::test]
async fn range_failures_obey_policy_and_local_positive_always_wins() {
    let redirect_target = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    redirect_target.set_nonblocking(true).unwrap();
    let redirect = format!(
        "HTTP/1.1 302 Found\r\nLocation: http://{}/leak\r\nContent-Length: 0\r\n\r\n",
        redirect_target.local_addr().unwrap()
    );
    // Otherwise-valid positive bodies distinguish each failure from parser failure.
    let digest = hex::encode_upper(sha1::Sha1::digest(b"candidate"));
    let positive = format!("{}:1\r\n", &digest[5..]);
    let oversized_chunked = format!(
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{:X}\r\n{positive}\r\n0\r\n\r\n",
        positive.len()
    )
    .into_bytes();
    for (wire, delay, timeout, bound) in [
        (response(""), 0, 1000, 1024),
        (response("malformed"), 0, 1000, 1024),
        (response(b"\xff"), 0, 1000, 1024),
        (
            response(format!("{}:not-a-count", "A".repeat(35))),
            0,
            1000,
            1024,
        ),
        (
            String::from_utf8(response(&positive))
                .unwrap()
                .replace("200 OK", "503 Unavailable")
                .into_bytes(),
            0,
            1000,
            1024,
        ),
        (redirect.into_bytes(), 0, 1000, 1024),
        (response(&positive), 250, 100, 1024),
        (oversized_chunked, 0, 1000, 16),
    ] {
        let (mut screening, task) = fixture(wire.clone(), delay, timeout, bound).await;
        assert_eq!(screening.check("candidate").await, Err(unavailable()));
        task.await.unwrap();
        let (allow, task) = fixture(wire, delay, timeout, bound).await;
        screening.range = allow.range;
        screening.on_unavailable = ScreeningUnavailable::Allow;
        assert_eq!(screening.check("candidate").await, Ok(()));
        task.await.unwrap();
    }
    assert_eq!(
        redirect_target.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    // No service is contacted when the local source already has a positive match.
    let mut cfg = config();
    cfg.sha256_hex = vec![hex::encode(Sha256::digest(b"listed"))];
    cfg.max_retries = 2;
    cfg.range_url = Some(format!(
        "https://{}/range",
        redirect_target.local_addr().unwrap()
    ));
    for policy in [ScreeningUnavailable::Deny, ScreeningUnavailable::Allow] {
        cfg.on_unavailable = policy;
        assert_eq!(
            PasswordScreening::new(&cfg).unwrap().check("listed").await,
            Err(not_allowed())
        );
    }
    assert_eq!(
        redirect_target.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

// Keep accepting until check() completes so a forbidden retry cannot go unnoticed.
async fn retry_fixture(
    replies: Vec<(Vec<u8>, u64)>,
) -> (
    PasswordScreening,
    tokio::sync::oneshot::Sender<()>,
    tokio::task::JoinHandle<Vec<(String, tokio::time::Instant)>>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (stop, mut stopped) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async move {
        let mut requests = Vec::new();
        loop {
            let (mut stream, _) = tokio::select! {
                _ = &mut stopped => break,
                accepted = listener.accept() => accepted.unwrap(),
            };
            let at = tokio::time::Instant::now();
            let mut request = Vec::new();
            let mut byte = [0; 1];
            while !request.ends_with(b"\r\n\r\n") {
                stream.read_exact(&mut byte).await.unwrap();
                request.push(byte[0]);
            }
            let (wire, delay_ms) = &replies[requests.len().min(replies.len() - 1)];
            requests.push((String::from_utf8(request).unwrap(), at));
            if *delay_ms > 0 {
                let split = wire.windows(4).position(|b| b == b"\r\n\r\n").unwrap() + 4;
                stream.write_all(&wire[..split]).await.unwrap();
                tokio::time::sleep(Duration::from_millis(*delay_ms)).await;
                let _ = stream.write_all(&wire[split..]).await;
            } else {
                let _ = stream.write_all(wire).await;
            }
        }
        requests
    });
    let mut screening = PasswordScreening::new(&config()).unwrap();
    screening.range.as_mut().unwrap().1 = format!("http://{address}/range/").parse().unwrap();
    (screening, stop, task)
}

#[tokio::test]
async fn configured_retries_recover_transient_failures_with_same_prefix_and_padding() {
    let digest = hex::encode_upper(sha1::Sha1::digest(b"candidate"));
    let positive = response(format!("{}:1\r\n", &digest[5..]));
    for (case, first) in [
        (
            b"HTTP/1.1 429 Limited\r\nContent-Length: 0\r\n\r\n".to_vec(),
            0,
        ),
        (
            b"HTTP/1.1 503 Unavailable\r\nContent-Length: 0\r\n\r\n".to_vec(),
            0,
        ),
        (Vec::new(), 0), // connection closes before headers
        (
            b"HTTP/1.1 200 OK\r\nContent-Length: 99\r\n\r\nshort".to_vec(),
            0,
        ),
        (positive.clone(), 150), // headers arrive, body times out
    ]
    .into_iter()
    .enumerate()
    {
        let (mut screening, stop, task) = retry_fixture(vec![first, (positive.clone(), 0)]).await;
        let mut cfg = config();
        cfg.max_retries = 1;
        cfg.retry_delay_ms = 70;
        cfg.timeout_ms = 100;
        cfg.max_response_bytes = positive.len();
        cfg.on_unavailable = ScreeningUnavailable::Allow;
        let url = screening.range.take().unwrap().1;
        screening = PasswordScreening::new(&cfg).unwrap();
        screening.range.as_mut().unwrap().1 = url;
        assert_eq!(
            screening.check("candidate").await,
            Err(not_allowed()),
            "case {case}"
        );
        stop.send(()).unwrap();
        let requests = task.await.unwrap();
        assert_eq!(requests.len(), 2);
        assert!(requests[1].1.duration_since(requests[0].1) >= Duration::from_millis(70));
        assert_eq!(requests[0].0, requests[1].0);
        assert!(
            requests[0]
                .0
                .starts_with(&format!("GET /range/{} HTTP/1.1\r\n", &digest[..5]))
        );
        assert!(
            requests[0]
                .0
                .to_ascii_lowercase()
                .contains("add-padding: true\r\n")
        );
        assert!(!requests[0].0.contains(&digest[5..]));
    }
}

#[tokio::test]
async fn retries_are_opt_in_bounded_and_follow_unavailable_policy_on_exhaustion() {
    let wire = b"HTTP/1.1 503 Unavailable\r\nContent-Length: 0\r\n\r\n".to_vec();
    for retries in [0, 2] {
        for policy in [ScreeningUnavailable::Deny, ScreeningUnavailable::Allow] {
            let (mut screening, stop, task) = retry_fixture(vec![(wire.clone(), 0)]).await;
            if retries > 0 {
                screening.max_retries = retries;
                screening.retry_delay = Duration::ZERO;
            }
            screening.on_unavailable = policy;
            let expected = if policy == ScreeningUnavailable::Deny {
                Err(unavailable())
            } else {
                Ok(())
            };
            assert_eq!(screening.check("candidate").await, expected);
            stop.send(()).unwrap();
            assert_eq!(task.await.unwrap().len() as u64, retries + 1);
        }
    }
    // A valid negative result after a transient failure ends retries immediately.
    let negative = response(format!("{}:0\r\n", "A".repeat(35)));
    let (mut screening, stop, task) = retry_fixture(vec![(wire, 0), (negative, 0)]).await;
    screening.max_retries = 2;
    screening.retry_delay = Duration::ZERO;
    assert_eq!(screening.check("candidate").await, Ok(()));
    stop.send(()).unwrap();
    assert_eq!(task.await.unwrap().len(), 2);
}

#[tokio::test]
async fn configured_retries_never_repeat_terminal_responses() {
    let digest = hex::encode_upper(sha1::Sha1::digest(b"candidate"));
    for (wire, bound, expected) in [
        (
            response(format!("{}:1\r\n", &digest[5..])),
            1024,
            Err(not_allowed()),
        ),
        (response(format!("{}:0\r\n", &digest[5..])), 1024, Ok(())),
        (response("malformed"), 1024, Err(unavailable())),
        (
            response(format!("{}:1\r\n", &digest[5..])),
            16,
            Err(unavailable()),
        ),
        (
            b"HTTP/1.1 302 Found\r\nLocation: /other\r\nContent-Length: 0\r\n\r\n".to_vec(),
            1024,
            Err(unavailable()),
        ),
        (
            b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n".to_vec(),
            1024,
            Err(unavailable()),
        ),
    ] {
        // A retry would get a valid negative response, exposing even permanent-error retries.
        let negative = response(format!("{}:0\r\n", &digest[5..]));
        let (mut screening, stop, task) = retry_fixture(vec![(wire, 0), (negative, 0)]).await;
        screening.max_retries = 2;
        screening.retry_delay = Duration::ZERO;
        screening.max_response_bytes = bound;
        assert_eq!(screening.check("candidate").await, expected);
        stop.send(()).unwrap();
        assert_eq!(task.await.unwrap().len(), 1);
    }
}
