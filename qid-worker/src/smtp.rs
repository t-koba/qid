//! Optional SMTP notification transport.
//!
//! The notification `provider` URL is the server address: `smtp://host[:port]`
//! requires STARTTLS and `smtps://host[:port]` uses implicit TLS. There is no
//! plaintext mode. Credentials, query, fragment and path parts are rejected in
//! the provider URL; the sender address and credentials come only from the
//! `QID_SMTP_FROM`, `QID_SMTP_USERNAME` and `QID_SMTP_PASSWORD` environment
//! variables, and never appear in errors, logs or serialized job data.

#[cfg(feature = "smtp-transport")]
use lettre::message::Mailbox;
#[cfg(feature = "smtp-transport")]
use zeroize::Zeroizing;

#[cfg(feature = "smtp-transport")]
use crate::{NotificationChannel, NotificationRequest};

#[cfg(feature = "smtp-transport")]
use crate::{NotificationResponse, NotificationTransport};

/// How the SMTP session is encrypted. Plaintext delivery is not supported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SmtpTlsMode {
    /// `smtp://`: connect, then require a STARTTLS upgrade before any secret.
    StartTls,
    /// `smtps://`: TLS from the first byte.
    ImplicitTls,
}

/// Validated SMTP server address. Carries no secrets and is safe to log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmtpEndpoint {
    pub host: String,
    pub port: u16,
    pub tls: SmtpTlsMode,
}

/// True when `provider` selects the SMTP transport (`smtp://` or `smtps://`).
pub fn is_smtp_provider(provider: &str) -> bool {
    provider.split_once(':').is_some_and(|(scheme, _)| {
        scheme.eq_ignore_ascii_case("smtp") || scheme.eq_ignore_ascii_case("smtps")
    })
}

/// Parse and validate an SMTP provider URL.
///
/// Rejects unknown schemes, userinfo, query, fragment, paths and missing or
/// invalid hosts. All errors are static so they never echo configuration.
pub fn parse_smtp_endpoint(provider: &str) -> Result<SmtpEndpoint, &'static str> {
    let url = reqwest::Url::parse(provider)
        .map_err(|_| "SMTP provider must be an absolute smtp:// or smtps:// URL")?;
    let tls = match url.scheme() {
        "smtp" => SmtpTlsMode::StartTls,
        "smtps" => SmtpTlsMode::ImplicitTls,
        _ => return Err("SMTP provider must use smtp:// (STARTTLS) or smtps:// (implicit TLS)"),
    };
    if !url.username().is_empty() || url.password().is_some() {
        return Err("SMTP provider must not contain credentials");
    }
    if url.query().is_some() {
        return Err("SMTP provider must not contain a query");
    }
    if url.fragment().is_some() {
        return Err("SMTP provider must not contain a fragment");
    }
    if !url.path().is_empty() && url.path() != "/" {
        return Err("SMTP provider must not contain a path");
    }
    let host = url
        .host_str()
        .ok_or("SMTP provider must name a server host")?;
    let host = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host)
        .to_string();
    let port = url.port().unwrap_or(match tls {
        SmtpTlsMode::StartTls => 587,
        SmtpTlsMode::ImplicitTls => 465,
    });
    if port == 0 {
        return Err("SMTP provider must use a valid port");
    }
    Ok(SmtpEndpoint { host, port, tls })
}

/// SMTP sender and credentials from the runtime environment.
///
/// Secret-bearing: no `Debug`/`Serialize` impls, never logged or serialized.
#[cfg(feature = "smtp-transport")]
pub(crate) struct SmtpEnv {
    from: Mailbox,
    username: Option<String>,
    password: Zeroizing<String>,
}

/// Read the sender and optional credentials. The sender must be configured;
/// username and password must both be set or both be unset.
#[cfg(feature = "smtp-transport")]
pub(crate) fn read_smtp_env(
    get_env: &dyn Fn(&str) -> Option<String>,
) -> Result<SmtpEnv, &'static str> {
    let from = get_env("QID_SMTP_FROM")
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .ok_or("QID_SMTP_FROM sender is not configured")?
        .parse::<Mailbox>()
        .map_err(|_| "QID_SMTP_FROM sender is not a valid email address")?;
    let username = get_env("QID_SMTP_USERNAME")
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    let password = get_env("QID_SMTP_PASSWORD").filter(|value| !value.is_empty());
    match (username, password) {
        (None, None) => Ok(SmtpEnv {
            from,
            username: None,
            password: Zeroizing::new(String::new()),
        }),
        (Some(username), Some(password)) => Ok(SmtpEnv {
            from,
            username: Some(username),
            password: Zeroizing::new(password),
        }),
        _ => Err("QID_SMTP_USERNAME and QID_SMTP_PASSWORD must both be set or both be unset"),
    }
}

/// Validated SMTP message parts. The subject is empty when none was given.
#[cfg(feature = "smtp-transport")]
pub(crate) struct SmtpMessage {
    from: Mailbox,
    to: Mailbox,
    subject: String,
    body: String,
}

/// Format an email notification for SMTP. Rejects non-email channels.
#[cfg(feature = "smtp-transport")]
pub(crate) fn smtp_message(
    request: &NotificationRequest,
    from: &Mailbox,
) -> Result<SmtpMessage, &'static str> {
    if request.channel != NotificationChannel::Email {
        return Err("SMTP transport only supports email notifications");
    }
    let to = request
        .recipient
        .parse::<Mailbox>()
        .map_err(|_| "SMTP recipient is not a valid email address")?;
    Ok(SmtpMessage {
        from: from.clone(),
        to,
        subject: request.subject.clone().unwrap_or_default(),
        body: request.body.clone(),
    })
}

#[cfg(feature = "smtp-transport")]
use lettre::{AsyncSmtpTransport, AsyncTransport, Tokio1Executor};

/// SMTP [`NotificationTransport`]. Credentials and sender are not serialized or logged.
#[cfg(feature = "smtp-transport")]
pub struct SmtpTransport {
    inner: AsyncSmtpTransport<Tokio1Executor>,
    from: Mailbox,
}

#[cfg(feature = "smtp-transport")]
impl SmtpTransport {
    /// Build from a provider URL and the process environment.
    pub fn from_env(provider: &str, timeout_secs: u64) -> Result<Self, String> {
        Self::build(provider, timeout_secs, &[], &|key| std::env::var(key).ok())
    }

    pub(crate) fn build(
        provider: &str,
        timeout_secs: u64,
        extra_roots_der: &[Vec<u8>],
        get_env: &dyn Fn(&str) -> Option<String>,
    ) -> Result<Self, String> {
        if timeout_secs == 0 {
            return Err("SMTP timeout must be greater than zero".to_string());
        }
        let endpoint = parse_smtp_endpoint(provider).map_err(str::to_owned)?;
        let env = read_smtp_env(get_env).map_err(str::to_owned)?;
        let mut tls =
            lettre::transport::smtp::client::TlsParameters::builder(endpoint.host.clone());
        for der in extra_roots_der {
            let root = lettre::transport::smtp::client::Certificate::from_der(der.clone())
                .map_err(|_| "invalid SMTP root certificate".to_string())?;
            tls = tls.add_root_certificate(root);
        }
        let tls = tls
            .build()
            .map_err(|error| format!("failed to configure SMTP TLS: {error}"))?;
        let tls = match endpoint.tls {
            SmtpTlsMode::StartTls => lettre::transport::smtp::client::Tls::Required(tls),
            SmtpTlsMode::ImplicitTls => lettre::transport::smtp::client::Tls::Wrapper(tls),
        };
        let mut builder = AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(endpoint.host)
            .port(endpoint.port)
            .tls(tls)
            .timeout(Some(std::time::Duration::from_secs(timeout_secs)));
        if let Some(username) = env.username {
            let secret: String = (*env.password).clone();
            builder = builder.credentials(
                lettre::transport::smtp::authentication::Credentials::new(username, secret),
            );
        }
        Ok(Self {
            inner: builder.build(),
            from: env.from,
        })
    }
}

#[cfg(feature = "smtp-transport")]
#[async_trait::async_trait]
impl NotificationTransport for SmtpTransport {
    async fn send(&self, request: NotificationRequest) -> Result<NotificationResponse, String> {
        let message = smtp_message(&request, &self.from).map_err(str::to_owned)?;
        let mut composed = lettre::Message::builder().from(message.from).to(message.to);
        if !message.subject.is_empty() {
            composed = composed.subject(message.subject.clone());
        }
        let email = composed
            .header(lettre::message::header::ContentType::TEXT_PLAIN)
            .body(message.body.clone())
            .map_err(|_| "failed to build SMTP message".to_string())?;
        let response = self
            .inner
            .send(email)
            .await
            .map_err(|_| "SMTP delivery failed".to_string())?;
        Ok(NotificationResponse {
            status: u16::from(response.code()),
            provider_message_id: None,
            sent: true,
        })
    }
}

#[cfg(test)]
#[path = "tests/smtp_test.rs"]
mod smtp_test;
