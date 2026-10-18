//! QUIC transport listener.
//!
//! Provides an RFC 9000-compatible QUIC listener backed by the `quinn`
//! crate. Listens on a configured UDP socket and accepts incoming
//! connections.
//!
//! Feature-gated behind `quic`.

use qid_core::error::{QidError, QidResult};
use std::net::SocketAddr;
use std::sync::Arc;

/// Configuration for a QUIC listener.
#[derive(Debug, Clone)]
pub struct QuicListenerConfig {
    pub bind_address: String,
    pub certificate_der: Vec<u8>,
    pub private_key_der: Vec<u8>,
    pub max_concurrent_bidi_streams: u32,
}

impl Default for QuicListenerConfig {
    fn default() -> Self {
        Self {
            bind_address: "[::]:4433".to_string(),
            certificate_der: Vec::new(),
            private_key_der: Vec::new(),
            max_concurrent_bidi_streams: 100,
        }
    }
}

/// A QUIC listener that accepts mdoc / OID4VP connections.
///
/// Helper-level only: the listener accepts connections and drains streams
/// without claiming protocol interoperability.
pub struct QuicListener {
    config: QuicListenerConfig,
}

/// A bound QUIC endpoint that has completed TLS and socket setup.
pub struct BoundQuicListener {
    endpoint: quinn::Endpoint,
}

impl QuicListener {
    pub fn new(config: QuicListenerConfig) -> Self {
        Self { config }
    }

    /// Validate configuration and bind the UDP socket plus TLS state.
    ///
    /// Binding is synchronous with startup reporting: a returned endpoint
    /// means `serve` can accept connections immediately.
    pub fn bind(&self) -> QidResult<BoundQuicListener> {
        if self.config.certificate_der.is_empty() || self.config.private_key_der.is_empty() {
            return Err(QidError::Config {
                message: "QUIC is not configured: certificate and private key are required"
                    .to_string(),
            });
        }

        let bind_addr: SocketAddr =
            self.config
                .bind_address
                .parse()
                .map_err(|e| QidError::Config {
                    message: format!(
                        "invalid QUIC bind address '{}': {e}",
                        self.config.bind_address
                    ),
                })?;

        let tls_config =
            build_tls_server_config(&self.config.certificate_der, &self.config.private_key_der)?;

        let quic_tls_config = quinn::crypto::rustls::QuicServerConfig::try_from(tls_config)
            .map_err(|e| QidError::Crypto {
                message: format!("failed to build QUIC TLS crypto config: {e}"),
            })?;
        let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_tls_config));
        let mut transport_config = quinn::TransportConfig::default();
        transport_config.max_concurrent_bidi_streams(quinn::VarInt::from_u32(
            self.config.max_concurrent_bidi_streams,
        ));
        server_config.transport_config(Arc::new(transport_config));

        let endpoint =
            quinn::Endpoint::server(server_config, bind_addr).map_err(|e| QidError::Internal {
                message: format!("failed to bind QUIC endpoint to {}: {e}", bind_addr),
            })?;

        tracing::info!(
            "QUIC listener bound to {} with max_bidi_streams={}",
            bind_addr,
            self.config.max_concurrent_bidi_streams,
        );

        Ok(BoundQuicListener { endpoint })
    }

    /// Bind, then serve until the endpoint closes.
    pub async fn listen(&self) -> QidResult<()> {
        let bound = self.bind()?;
        bound.serve().await
    }

    /// Bind, then serve until `shutdown` resolves or the endpoint closes.
    pub async fn listen_with_shutdown(
        &self,
        shutdown: tokio::sync::oneshot::Receiver<()>,
    ) -> QidResult<()> {
        let bound = self.bind()?;
        bound.serve_with_shutdown(shutdown).await
    }
}

impl BoundQuicListener {
    /// Serve until the endpoint closes.
    pub async fn serve(self) -> QidResult<()> {
        run_accept_loop(self.endpoint, None).await
    }

    /// Serve until `shutdown` resolves or the endpoint closes.
    pub async fn serve_with_shutdown(
        self,
        shutdown: tokio::sync::oneshot::Receiver<()>,
    ) -> QidResult<()> {
        run_accept_loop(self.endpoint, Some(shutdown)).await
    }
}

async fn run_accept_loop(
    endpoint: quinn::Endpoint,
    shutdown: Option<tokio::sync::oneshot::Receiver<()>>,
) -> QidResult<()> {
    let mut shutdown = shutdown;
    loop {
        if let Some(receiver) = shutdown.as_mut() {
            tokio::select! {
                _ = receiver => {
                    tracing::info!("QUIC listener shutdown requested, closing endpoint");
                    endpoint.close(0u32.into(), b"shutdown");
                    return Ok(());
                }
                incoming = endpoint.accept() => {
                    if !accept_incoming(incoming).await {
                        return Ok(());
                    }
                }
            }
        } else if !accept_incoming(endpoint.accept().await).await {
            return Ok(());
        }
    }
}

/// Accept one incoming connection; returns false when the endpoint closed.
async fn accept_incoming(incoming: Option<quinn::Incoming>) -> bool {
    match incoming {
        Some(incoming) => {
            let remote = incoming.remote_address();
            tracing::debug!("QUIC connection attempt from {remote}");
            match incoming.accept() {
                Ok(connecting) => {
                    tokio::spawn(async move {
                        if let Err(e) = handle_connection(connecting).await {
                            tracing::warn!("QUIC connection from {remote} failed: {e}");
                        }
                    });
                }
                Err(e) => {
                    tracing::warn!("QUIC connection from {remote} rejected: {e}");
                }
            }
            true
        }
        None => {
            tracing::info!("QUIC endpoint closed, terminating listener");
            false
        }
    }
}

async fn handle_connection(connecting: quinn::Connecting) -> QidResult<()> {
    let connection = connecting.await.map_err(|e| QidError::Internal {
        message: format!("QUIC handshake failed: {e}"),
    })?;
    let remote = connection.remote_address();
    tracing::info!("QUIC connection established from {remote}");

    loop {
        match connection.accept_bi().await {
            Ok((_send, recv)) => {
                tokio::spawn(async move {
                    handle_stream(recv).await;
                });
            }
            Err(quinn::ConnectionError::ApplicationClosed { .. }) => {
                tracing::debug!("QUIC connection to {remote} closed by peer");
                return Ok(());
            }
            Err(e) => {
                tracing::warn!("QUIC stream error from {remote}: {e}");
                return Ok(());
            }
        }
    }
}

async fn handle_stream(mut recv: quinn::RecvStream) {
    match recv.read_to_end(1024 * 1024).await {
        Ok(buf) => {
            tracing::debug!("QUIC stream read {} byte(s)", buf.len());
        }
        Err(e) => {
            tracing::warn!("QUIC stream read error: {e}");
        }
    }
}

fn build_tls_server_config(
    certificate_der: &[u8],
    private_key_der: &[u8],
) -> QidResult<rustls::ServerConfig> {
    let cert_chain = if certificate_der.starts_with(b"-----BEGIN ") {
        let mut certificate_reader = certificate_der;
        let certs = rustls_pemfile::certs(&mut certificate_reader)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| QidError::Crypto {
                message: format!("failed to parse QUIC TLS certificate PEM: {e}"),
            })?;
        if certs.is_empty() {
            return Err(QidError::Crypto {
                message: "QUIC TLS certificate PEM contains no certificates".to_string(),
            });
        }
        certs
    } else {
        vec![rustls::pki_types::CertificateDer::from(
            certificate_der.to_vec(),
        )]
    };

    let key = if private_key_der.starts_with(b"-----BEGIN ") {
        let mut private_key_reader = private_key_der;
        rustls_pemfile::private_key(&mut private_key_reader)
            .map_err(|e| QidError::Crypto {
                message: format!("failed to parse QUIC TLS private key PEM: {e}"),
            })?
            .ok_or_else(|| QidError::Crypto {
                message: "QUIC TLS private key PEM contains no keys".to_string(),
            })?
    } else {
        rustls::pki_types::PrivatePkcs8KeyDer::from(private_key_der.to_vec()).into()
    };

    let tls_config =
        rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_no_client_auth()
            .with_single_cert(cert_chain, key)
            .map_err(|e| QidError::Crypto {
                message: format!("failed to build QUIC TLS server config: {e}"),
            })?;

    Ok(tls_config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn listener_config_default() {
        let config = QuicListenerConfig::default();
        assert_eq!(config.bind_address, "[::]:4433");
        assert!(config.certificate_der.is_empty());
        assert!(config.private_key_der.is_empty());
        assert_eq!(config.max_concurrent_bidi_streams, 100);
    }

    #[tokio::test]
    async fn listener_returns_error_without_certificates() {
        let config = QuicListenerConfig::default();
        let listener = QuicListener::new(config);
        let err = listener.listen().await.unwrap_err();
        assert!(err.message().contains("QUIC is not configured"));
    }

    #[test]
    fn bind_fails_fast_without_certificates() {
        let listener = QuicListener::new(QuicListenerConfig::default());
        let err = match listener.bind() {
            Ok(_) => panic!("bind must fail without certificates"),
            Err(err) => err,
        };
        assert!(err.message().contains("QUIC is not configured"));
    }

    #[test]
    fn bind_rejects_invalid_bind_address() {
        let listener = QuicListener::new(QuicListenerConfig {
            bind_address: "not-a-socket-address".to_string(),
            certificate_der: vec![0x30, 0x82, 0x01],
            private_key_der: vec![0x30, 0x82, 0x01],
            max_concurrent_bidi_streams: 100,
        });
        let err = match listener.bind() {
            Ok(_) => panic!("bind must fail with an invalid bind address"),
            Err(err) => err,
        };
        assert!(err.message().contains("invalid QUIC bind address"));
    }
}
