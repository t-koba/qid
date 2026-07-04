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
pub struct QuicListener {
    config: QuicListenerConfig,
}

impl QuicListener {
    pub fn new(config: QuicListenerConfig) -> Self {
        Self { config }
    }

    pub async fn listen(&self) -> QidResult<()> {
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

        loop {
            match endpoint.accept().await {
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
                }
                None => {
                    tracing::info!("QUIC endpoint closed, terminating listener");
                    break;
                }
            }
        }

        Ok(())
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
    let mut cert_chain = Vec::new();
    if certificate_der.starts_with(b"-----BEGIN ") {
        let certs = rustls_pemfile::certs(&mut certificate_der.as_ref())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| QidError::Crypto {
                message: format!("failed to parse QUIC TLS certificate PEM: {e}"),
            })?;
        if certs.is_empty() {
            return Err(QidError::Crypto {
                message: "QUIC TLS certificate PEM contains no certificates".to_string(),
            });
        }
        cert_chain = certs
            .into_iter()
            .map(rustls::pki_types::CertificateDer::from)
            .collect();
    } else {
        cert_chain.push(rustls::pki_types::CertificateDer::from(
            certificate_der.to_vec(),
        ));
    }

    let key = if private_key_der.starts_with(b"-----BEGIN ") {
        rustls_pemfile::private_key(&mut private_key_der.as_ref())
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
}
