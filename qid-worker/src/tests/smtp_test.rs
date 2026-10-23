use super::*;
#[cfg(feature = "smtp-transport")]
use crate::{NotificationChannel, NotificationRequest};
#[cfg(feature = "smtp-transport")]
use std::collections::HashMap;

#[cfg(feature = "smtp-transport")]
fn email_request(
    channel: NotificationChannel,
    provider: &str,
    recipient: &str,
    subject: Option<&str>,
) -> NotificationRequest {
    NotificationRequest {
        channel,
        provider: provider.to_string(),
        recipient: recipient.to_string(),
        subject: subject.map(str::to_string),
        body: "message body".to_string(),
        template_id: None,
        data_json: serde_json::json!({}),
    }
}

#[cfg(feature = "smtp-transport")]
fn env_lookup(store: &HashMap<String, String>) -> impl Fn(&str) -> Option<String> + '_ {
    move |key| store.get(key).cloned()
}

#[cfg(feature = "smtp-transport")]
fn env_store(pairs: &[(&str, &str)]) -> HashMap<String, String> {
    pairs
        .iter()
        .map(|(key, value)| ((*key).to_string(), (*value).to_string()))
        .collect()
}

#[test]
fn smtp_endpoint_accepts_starttls_and_implicit_tls_defaults() {
    let starttls = parse_smtp_endpoint("smtp://mail.example.com").expect("STARTTLS endpoint");
    assert_eq!(
        starttls,
        SmtpEndpoint {
            host: "mail.example.com".to_string(),
            port: 587,
            tls: SmtpTlsMode::StartTls,
        }
    );
    let implicit = parse_smtp_endpoint("smtps://mail.example.com").expect("implicit endpoint");
    assert_eq!(implicit.port, 465);
    assert_eq!(implicit.tls, SmtpTlsMode::ImplicitTls);
    assert_eq!(
        parse_smtp_endpoint("smtp://mail.example.com:2587")
            .expect("custom port")
            .port,
        2587
    );
    assert!(is_smtp_provider("smtp://mail.example.com"));
    assert!(is_smtp_provider("smtps://mail.example.com:465"));
    assert!(!is_smtp_provider("https://mail.example.com/hook"));
    assert!(!is_smtp_provider("not-a-url"));
}

#[test]
fn smtp_endpoint_rejects_unsafe_or_ambiguous_urls() {
    for provider in [
        "https://mail.example.com/hook",
        "http://mail.example.com",
        "smtp://user:pass@mail.example.com",
        "smtp://user@mail.example.com",
        "smtps://mail.example.com:465?tls=required",
        "smtp://mail.example.com#fragment",
        "smtp://mail.example.com/ehlo-name",
        "smtp://",
        "smtp://:587",
        "mail.example.com",
        "",
    ] {
        assert!(
            parse_smtp_endpoint(provider).is_err(),
            "provider must be rejected"
        );
    }
}

#[cfg(feature = "smtp-transport")]
#[test]
fn smtp_env_requires_sender_and_paired_credentials() {
    let empty: HashMap<String, String> = HashMap::new();
    assert_eq!(
        read_smtp_env(&env_lookup(&empty)).err(),
        Some("QID_SMTP_FROM sender is not configured")
    );
    let bad_sender = env_store(&[("QID_SMTP_FROM", "not-an-email")]);
    assert_eq!(
        read_smtp_env(&env_lookup(&bad_sender)).err(),
        Some("QID_SMTP_FROM sender is not a valid email address")
    );
    let username_only = env_store(&[
        ("QID_SMTP_FROM", "qid@example.com"),
        ("QID_SMTP_USERNAME", "smtp-user"),
    ]);
    assert_eq!(
        read_smtp_env(&env_lookup(&username_only)).err(),
        Some("QID_SMTP_USERNAME and QID_SMTP_PASSWORD must both be set or both be unset")
    );
    let password_only = env_store(&[
        ("QID_SMTP_FROM", "qid@example.com"),
        ("QID_SMTP_PASSWORD", "smtp-pass"),
    ]);
    assert_eq!(
        read_smtp_env(&env_lookup(&password_only)).err(),
        Some("QID_SMTP_USERNAME and QID_SMTP_PASSWORD must both be set or both be unset")
    );
    let bare = env_store(&[("QID_SMTP_FROM", "qid@example.com")]);
    let env = read_smtp_env(&env_lookup(&bare)).expect("sender without auth");
    assert_eq!(env.from.to_string(), "qid@example.com");
    assert!(env.username.is_none());
    assert!(env.password.is_empty());
    let full = env_store(&[
        ("QID_SMTP_FROM", "qid@example.com"),
        ("QID_SMTP_USERNAME", "smtp-user"),
        ("QID_SMTP_PASSWORD", "smtp-pass"),
    ]);
    let env = read_smtp_env(&env_lookup(&full)).expect("sender with auth");
    assert_eq!(env.username.as_deref(), Some("smtp-user"));
}

#[cfg(feature = "smtp-transport")]
#[test]
fn smtp_message_rejects_push_and_bad_addresses() {
    let push = email_request(
        NotificationChannel::Push,
        "smtp://mail.example.com",
        "device-token",
        None,
    );
    let sender = "qid@example.com".parse().expect("sender mailbox");
    assert_eq!(
        smtp_message(&push, &sender).err(),
        Some("SMTP transport only supports email notifications")
    );
    let bad_recipient = email_request(
        NotificationChannel::Email,
        "smtp://mail.example.com",
        "not-an-email",
        None,
    );
    assert_eq!(
        smtp_message(&bad_recipient, &sender).err(),
        Some("SMTP recipient is not a valid email address")
    );
}

#[cfg(feature = "smtp-transport")]
#[test]
fn smtp_message_keeps_email_semantics() {
    let request = email_request(
        NotificationChannel::Email,
        "smtp://mail.example.com",
        "alice@example.com",
        Some("Verify your email"),
    );
    let message =
        smtp_message(&request, &"qid@example.com".parse().unwrap()).expect("email message");
    assert_eq!(message.from.to_string(), "qid@example.com");
    assert_eq!(message.to.to_string(), "alice@example.com");
    assert_eq!(message.subject, "Verify your email");
    assert_eq!(message.body, "message body");
    let without_subject = email_request(
        NotificationChannel::Email,
        "smtp://mail.example.com",
        "alice@example.com",
        None,
    );
    let message =
        smtp_message(&without_subject, &"qid@example.com".parse().unwrap()).expect("no subject");
    assert!(message.subject.is_empty());
}

#[cfg(feature = "smtp-transport")]
#[test]
fn smtp_message_accepts_single_label_relay_mailboxes() {
    // Lettre's Mailbox accepts single-label relay domains; do not impose a dot rule.
    let request = email_request(
        NotificationChannel::Email,
        "smtp://localhost",
        "postmaster@localhost",
        None,
    );
    let sender = "postmaster@localhost"
        .parse()
        .expect("relay sender mailbox");
    let message = smtp_message(&request, &sender).expect("single-label relay message");
    assert_eq!(message.from.to_string(), "postmaster@localhost");
    assert_eq!(message.to.to_string(), "postmaster@localhost");
}

#[cfg(feature = "smtp-transport")]
mod exchange {
    use super::super::{SmtpTransport, parse_smtp_endpoint};
    use crate::{NotificationChannel, NotificationRequest, NotificationTransport};
    use base64::Engine as _;
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt};

    #[derive(Default)]
    struct FakeSmtpState {
        tls_completed: bool,
        plaintext_commands: Vec<String>,
        auth_blob: Option<String>,
        mail_from: Option<String>,
        rcpt_to: Vec<String>,
        data: Vec<u8>,
    }

    async fn write_line(writer: &mut (impl tokio::io::AsyncWrite + Unpin), line: &str) {
        writer
            .write_all(format!("{line}\r\n").as_bytes())
            .await
            .unwrap();
    }

    async fn read_line(reader: &mut (impl tokio::io::AsyncBufRead + Unpin)) -> String {
        let mut raw = Vec::new();
        reader.read_until(b'\n', &mut raw).await.unwrap();
        let text = String::from_utf8(raw).unwrap();
        text.strip_suffix("\r\n")
            .or_else(|| text.strip_suffix('\n'))
            .unwrap_or(&text)
            .to_string()
    }

    async fn serve_connection(
        stream: tokio::net::TcpStream,
        acceptor: tokio_rustls::TlsAcceptor,
        state: Arc<Mutex<FakeSmtpState>>,
    ) {
        let Ok(tls) = acceptor.accept(stream).await else {
            return;
        };
        serve_tls_exchange(tls, state, true).await;
    }

    async fn serve_tls_exchange(
        tls: impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
        state: Arc<Mutex<FakeSmtpState>>,
        send_greeting: bool,
    ) {
        state.lock().unwrap().tls_completed = true;
        let (reader, writer) = tokio::io::split(tls);
        let mut reader = tokio::io::BufReader::new(reader);
        let mut writer = writer;
        if send_greeting {
            write_line(&mut writer, "220 localhost ESMTP fake").await;
        }
        loop {
            let line = read_line(&mut reader).await;
            if line.starts_with("EHLO") || line.starts_with("HELO") {
                write_line(&mut writer, "250-localhost").await;
                write_line(&mut writer, "250 AUTH PLAIN LOGIN").await;
            } else if let Some(blob) = line.strip_prefix("AUTH PLAIN ") {
                state.lock().unwrap().auth_blob = Some(blob.trim().to_string());
                write_line(&mut writer, "235 2.7.0 Accepted").await;
            } else if let Some(sender) = line.strip_prefix("MAIL FROM:") {
                state.lock().unwrap().mail_from = Some(sender.trim().to_string());
                write_line(&mut writer, "250 OK").await;
            } else if let Some(recipient) = line.strip_prefix("RCPT TO:") {
                state
                    .lock()
                    .unwrap()
                    .rcpt_to
                    .push(recipient.trim().to_string());
                write_line(&mut writer, "250 OK").await;
            } else if line == "DATA" {
                write_line(&mut writer, "354 End with .").await;
                let mut body = Vec::new();
                loop {
                    let chunk = read_line(&mut reader).await;
                    if chunk == "." {
                        break;
                    }
                    body.extend_from_slice(chunk.as_bytes());
                    body.extend_from_slice(b"\r\n");
                }
                state.lock().unwrap().data = body;
                write_line(&mut writer, "250 OK queued").await;
            } else if line == "QUIT" {
                write_line(&mut writer, "221 Bye").await;
                break;
            } else if line == "RSET" || line == "NOOP" {
                write_line(&mut writer, "250 OK").await;
            } else {
                write_line(&mut writer, "502 unimplemented").await;
            }
        }
    }

    fn tls_fixture() -> (tokio_rustls::TlsAcceptor, Vec<u8>) {
        let certified = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string()]).unwrap();
        let cert_der = certified.cert.der().to_vec();
        let key_der = certified.key_pair.serialize_der();
        let server_config = rustls::ServerConfig::builder_with_provider(
            rustls::crypto::ring::default_provider().into(),
        )
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![rustls::pki_types::CertificateDer::from(cert_der.clone())],
            rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(
                key_der,
            )),
        )
        .unwrap();
        (
            tokio_rustls::TlsAcceptor::from(Arc::new(server_config)),
            cert_der,
        )
    }

    #[tokio::test]
    async fn smtp_fake_exchange_delivers_only_after_tls() {
        let (acceptor, cert_der) = tls_fixture();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let state = Arc::new(Mutex::new(FakeSmtpState::default()));
        let server = tokio::spawn({
            let (acceptor, state) = (acceptor.clone(), state.clone());
            async move {
                loop {
                    let Ok((stream, _)) = listener.accept().await else {
                        break;
                    };
                    serve_connection(stream, acceptor.clone(), state.clone()).await;
                }
            }
        });

        let provider = format!("smtps://127.0.0.1:{port}");
        assert_eq!(
            parse_smtp_endpoint(&provider)
                .expect("loopback endpoint")
                .port,
            port
        );
        let env: HashMap<String, String> = [
            ("QID_SMTP_FROM".to_string(), "qid@example.com".to_string()),
            ("QID_SMTP_USERNAME".to_string(), "smtp-user".to_string()),
            ("QID_SMTP_PASSWORD".to_string(), "smtp-pass".to_string()),
        ]
        .into_iter()
        .collect();
        let request = NotificationRequest {
            channel: NotificationChannel::Email,
            provider: provider.clone(),
            recipient: "alice@example.com".to_string(),
            subject: Some("Verify your email".to_string()),
            body: "Use code 123456".to_string(),
            template_id: None,
            data_json: serde_json::json!({}),
        };

        // Without the fixture root the handshake must fail: no delivery.
        let untrusted =
            SmtpTransport::build(&provider, 10, &[], &|key| env.get(key).cloned()).expect("build");
        assert!(
            NotificationTransport::send(&untrusted, request.clone())
                .await
                .is_err()
        );

        // With the fixture root delivery succeeds over the TLS session.
        let trusted =
            SmtpTransport::build(&provider, 10, &[cert_der], &|key| env.get(key).cloned())
                .expect("build");
        let response = NotificationTransport::send(&trusted, request)
            .await
            .expect("SMTP delivery");
        assert!(response.sent);
        assert_eq!(response.status, 250);
        assert_eq!(response.provider_message_id, None);

        let state = state.lock().unwrap();
        assert!(state.tls_completed);
        assert_eq!(state.mail_from.as_deref(), Some("<qid@example.com>"));
        assert_eq!(state.rcpt_to, vec!["<alice@example.com>".to_string()]);
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(state.auth_blob.as_deref().unwrap_or_default())
            .unwrap_or_default();
        assert_eq!(decoded, b"\0smtp-user\0smtp-pass");
        let data = String::from_utf8(state.data.clone()).expect("message bytes");
        assert!(data.contains("Verify your email"));
        assert!(data.contains("Use code 123456"));
        assert!(!data.contains("smtp-pass"));
        server.abort();
    }

    #[tokio::test]
    async fn smtp_starttls_refuses_plaintext_fallback_when_not_advertised() {
        use std::time::Duration;
        use tokio::time::timeout;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let provider = format!("smtp://127.0.0.1:{}", listener.local_addr().unwrap().port());
        let server = tokio::spawn(async move {
            timeout(Duration::from_secs(10), async move {
                let (stream, _) = listener.accept().await.unwrap();
                let mut plaintext = tokio::io::BufReader::new(stream);
                let mut commands = Vec::new();
                write_line(plaintext.get_mut(), "220 localhost ESMTP fake").await;
                loop {
                    let line = read_line(&mut plaintext).await;
                    if line.is_empty() {
                        break;
                    }
                    commands.push(line.clone());
                    if line.starts_with("EHLO ") {
                        // Offer authentication, but deliberately omit STARTTLS. An
                        // opportunistic client would now expose credentials or mail.
                        write_line(plaintext.get_mut(), "250-localhost").await;
                        write_line(plaintext.get_mut(), "250 AUTH PLAIN LOGIN").await;
                    } else if line == "QUIT" {
                        write_line(plaintext.get_mut(), "221 Bye").await;
                        break;
                    } else {
                        // Record any attempted fallback before closing the connection.
                        break;
                    }
                }
                commands
            })
            .await
            .expect("plaintext server timed out")
        });
        let env = super::env_store(&[
            ("QID_SMTP_FROM", "qid@example.com"),
            ("QID_SMTP_USERNAME", "smtp-user"),
            ("QID_SMTP_PASSWORD", "smtp-pass"),
        ]);
        let transport = SmtpTransport::build(&provider, 5, &[], &super::env_lookup(&env))
            .expect("STARTTLS transport");
        let request = super::email_request(
            NotificationChannel::Email,
            &provider,
            "alice@example.com",
            Some("Verify your email"),
        );
        let response = timeout(Duration::from_secs(5), transport.send(request)).await;
        // Join before assertions so neither failure path leaves a server task running.
        let commands = server.await.expect("plaintext server task");
        assert!(response.expect("STARTTLS client timed out").is_err());
        assert!(
            commands
                .first()
                .is_some_and(|line| line.starts_with("EHLO "))
        );
        for command in &commands {
            let verb = command.split_whitespace().next().unwrap_or_default();
            assert!(
                !["AUTH", "MAIL", "RCPT", "DATA"].contains(&verb),
                "sensitive SMTP command sent without TLS"
            );
        }
    }

    #[tokio::test]
    async fn smtp_starttls_exchange_delivers_only_after_upgrade() {
        use std::time::Duration;
        use tokio::time::timeout;

        let (acceptor, cert_der) = tls_fixture();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let provider = format!("smtp://127.0.0.1:{}", listener.local_addr().unwrap().port());
        let state = Arc::new(Mutex::new(FakeSmtpState::default()));
        let server = tokio::spawn({
            let state = state.clone();
            async move {
                timeout(Duration::from_secs(10), async move {
                    let (stream, _) = listener.accept().await.unwrap();
                    let mut plaintext = tokio::io::BufReader::new(stream);
                    write_line(plaintext.get_mut(), "220 localhost ESMTP fake").await;
                    loop {
                        let line = read_line(&mut plaintext).await;
                        state.lock().unwrap().plaintext_commands.push(line.clone());
                        if line.starts_with("EHLO ") {
                            // Authentication is advertised only after the upgrade.
                            write_line(plaintext.get_mut(), "250-localhost").await;
                            write_line(plaintext.get_mut(), "250 STARTTLS").await;
                        } else if line == "STARTTLS" {
                            assert!(
                                plaintext.buffer().is_empty(),
                                "pipelined plaintext after STARTTLS"
                            );
                            write_line(plaintext.get_mut(), "220 Ready to start TLS").await;
                            let tls = acceptor.accept(plaintext.into_inner()).await.unwrap();
                            serve_tls_exchange(tls, state, false).await;
                            break;
                        } else {
                            panic!("unexpected command before TLS");
                        }
                    }
                })
                .await
                .expect("STARTTLS server timed out");
            }
        });
        let env = super::env_store(&[
            ("QID_SMTP_FROM", "qid@example.com"),
            ("QID_SMTP_USERNAME", "smtp-user"),
            ("QID_SMTP_PASSWORD", "smtp-pass"),
        ]);
        let transport = SmtpTransport::build(&provider, 5, &[cert_der], &super::env_lookup(&env))
            .expect("STARTTLS transport");
        let mut request = super::email_request(
            NotificationChannel::Email,
            &provider,
            "alice@example.com",
            Some("Verify your email"),
        );
        request.body = "Use code 123456".to_string();
        let response = timeout(Duration::from_secs(5), transport.send(request)).await;
        // Join before assertions so the bounded server is cleaned up even on delivery failure.
        server.await.expect("STARTTLS server task");
        let response = response
            .expect("STARTTLS client timed out")
            .expect("SMTP delivery");
        assert!(response.sent);
        assert_eq!(response.status, 250);
        assert_eq!(response.provider_message_id, None);

        let state = state.lock().unwrap();
        assert_eq!(state.plaintext_commands.len(), 2);
        assert!(state.plaintext_commands[0].starts_with("EHLO "));
        assert_eq!(state.plaintext_commands[1], "STARTTLS");
        for command in &state.plaintext_commands {
            let verb = command.split_whitespace().next().unwrap_or_default();
            assert!(!["AUTH", "MAIL", "RCPT", "DATA"].contains(&verb));
        }
        assert!(state.tls_completed);
        assert_eq!(state.mail_from.as_deref(), Some("<qid@example.com>"));
        assert_eq!(state.rcpt_to, vec!["<alice@example.com>".to_string()]);
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(state.auth_blob.as_deref().expect("post-TLS authentication"))
            .unwrap();
        assert_eq!(decoded, b"\0smtp-user\0smtp-pass");
        let data = String::from_utf8(state.data.clone()).expect("message bytes");
        assert!(data.contains("Verify your email"));
        assert!(data.contains("Use code 123456"));
        assert!(!data.contains("smtp-pass"));
    }
}
