use axum::Router;
use qid_core::config::TlsConfig;
use std::future::Future;
use tokio::net::TcpListener;

// Prefer rustls when both features are enabled, including in all-features builds.
#[cfg(all(feature = "tls-qid", not(feature = "tls-rustls")))]
mod qid_backend;
#[cfg(feature = "tls-rustls")]
mod rustls_backend;

/// Authenticated client leaf certificate thumbprint carried in HTTP request extensions.
#[derive(Clone, Debug)]
pub struct NativeTlsPeer {
    pub leaf_x5t_s256: String,
}

pub async fn serve_https(
    config: &TlsConfig,
    listener: TcpListener,
    app: Router,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> anyhow::Result<()> {
    #[cfg(feature = "tls-rustls")]
    {
        rustls_backend::serve_https(config, listener, app, shutdown).await
    }
    #[cfg(all(feature = "tls-qid", not(feature = "tls-rustls")))]
    {
        qid_backend::serve_https(config, listener, app, shutdown).await
    }
    #[cfg(not(any(feature = "tls-rustls", feature = "tls-qid")))]
    {
        compile_error!("qidd requires a TLS backend; enable tls-rustls (default) or tls-qid")
    }
}

/// Check backend readiness before reading configuration or opening listeners.
pub fn startup_guard() -> anyhow::Result<()> {
    #[cfg(all(feature = "tls-qid", not(feature = "tls-rustls")))]
    {
        qid_backend::startup_guard()
    }
    #[cfg(not(all(feature = "tls-qid", not(feature = "tls-rustls"))))]
    {
        Ok(())
    }
}
