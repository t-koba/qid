use axum::Router;
use qid_core::config::TlsConfig;
use std::future::Future;
use tokio::net::TcpListener;

pub(super) fn startup_guard() -> anyhow::Result<()> {
    anyhow::bail!(
        "tls-qid is an experimental skeleton and cannot serve; rebuild with the default tls-rustls backend"
    );
}

pub(super) async fn serve_https(
    _config: &TlsConfig,
    _listener: TcpListener,
    _app: Router,
    _shutdown: impl Future<Output = ()> + Send + 'static,
) -> anyhow::Result<()> {
    startup_guard()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The daemon calls the guard after CLI parsing and before loading any configuration.
    #[tokio::test]
    async fn skeleton_refuses_startup_and_https() {
        const EXPECTED: &str = "tls-qid is an experimental skeleton and cannot serve; rebuild with the default tls-rustls backend";
        assert_eq!(
            startup_guard().expect_err("startup must fail").to_string(),
            EXPECTED
        );

        let config = TlsConfig {
            cert: String::new(),
            key: String::new(),
            client_ca: None,
            client_crls: Vec::new(),
            ocsp_responses: Vec::new(),
        };
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("test listener");
        let error = serve_https(&config, listener, Router::new(), std::future::pending())
            .await
            .expect_err("serving HTTPS must fail");
        assert_eq!(error.to_string(), EXPECTED);
    }
}
