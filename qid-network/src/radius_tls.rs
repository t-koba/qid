//! RADIUS over TLS (RFC 6614) and RADIUS over DTLS (RFC 7360).

#[cfg(feature = "radius-tls")]
use qid_core::error::{QidError, QidResult};
#[cfg(feature = "radius-tls")]
use std::sync::Arc;
#[cfg(feature = "radius-tls")]
use tokio::io::{AsyncReadExt, AsyncWriteExt};
#[cfg(feature = "radius-tls")]
use tokio::net::{TcpListener, TcpStream};
#[cfg(feature = "radius-tls")]
use tokio_rustls::{TlsAcceptor, TlsConnector};

pub struct RadiusTlsConfig {
    pub server_address: String,
    pub server_port: u16,
    pub certificate_der: Vec<u8>,
    pub private_key_der: Vec<u8>,
    pub ca_certificate_der: Option<Vec<u8>>,
}

pub struct RadiusTlsTransport;

impl RadiusTlsTransport {
    pub fn new() -> Self {
        Self
    }
}

impl Default for RadiusTlsTransport {
    fn default() -> Self {
        Self::new()
    }
}

pub struct RadiusTlsServerConfig {
    pub bind_address: String,
    pub certificate_der: Vec<u8>,
    pub private_key_der: Vec<u8>,
    pub client_ca_certificate_der: Option<Vec<u8>>,
    pub shared_secret: Vec<u8>,
}

#[cfg(feature = "radius-tls")]
pub async fn send_radius_over_tls(config: &RadiusTlsConfig, packet: &[u8]) -> QidResult<Vec<u8>> {
    validate_radius_packet_length(packet)?;
    let server_name = rustls_pki_types::ServerName::try_from(config.server_address.clone())
        .map_err(|error| QidError::BadRequest {
            message: format!("RADIUS/TLS server name is invalid: {error}"),
        })?;
    let mut roots = rustls::RootCertStore::empty();
    if let Some(ca) = config.ca_certificate_der.as_ref() {
        roots
            .add(rustls_pki_types::CertificateDer::from(ca.clone()))
            .map_err(|error| QidError::BadRequest {
                message: format!("RADIUS/TLS CA certificate is invalid: {error}"),
            })?;
    } else {
        return Err(QidError::BadRequest {
            message: "RADIUS/TLS requires a pinned CA certificate".to_string(),
        });
    }
    let client_cert = rustls_pki_types::CertificateDer::from(config.certificate_der.clone());
    let client_key = rustls_pki_types::PrivateKeyDer::try_from(config.private_key_der.clone())
        .map_err(|error| QidError::BadRequest {
            message: format!("RADIUS/TLS client private key is invalid: {error}"),
        })?;
    let tls_config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_client_auth_cert(vec![client_cert], client_key)
        .map_err(|error| QidError::BadRequest {
            message: format!("RADIUS/TLS client certificate is invalid: {error}"),
        })?;
    let address = format!("{}:{}", config.server_address, config.server_port);
    let tcp = TcpStream::connect(address)
        .await
        .map_err(|error| QidError::Internal {
            message: format!("RADIUS/TLS TCP connection failed: {error}"),
        })?;
    let connector = TlsConnector::from(Arc::new(tls_config));
    let mut stream =
        connector
            .connect(server_name, tcp)
            .await
            .map_err(|error| QidError::Unauthorized {
                message: format!("RADIUS/TLS handshake failed: {error}"),
            })?;
    stream
        .write_all(packet)
        .await
        .map_err(|error| QidError::Internal {
            message: format!("RADIUS/TLS request write failed: {error}"),
        })?;
    let mut header = [0u8; 4];
    stream
        .read_exact(&mut header)
        .await
        .map_err(|error| QidError::Internal {
            message: format!("RADIUS/TLS response header read failed: {error}"),
        })?;
    let length = u16::from_be_bytes([header[2], header[3]]) as usize;
    if length < 20 {
        return Err(QidError::BadRequest {
            message: "RADIUS/TLS response length is shorter than 20 bytes".to_string(),
        });
    }
    let mut response = vec![0u8; length];
    response[..4].copy_from_slice(&header);
    stream
        .read_exact(&mut response[4..])
        .await
        .map_err(|error| QidError::Internal {
            message: format!("RADIUS/TLS response body read failed: {error}"),
        })?;
    Ok(response)
}

#[cfg(feature = "radius-tls")]
pub async fn run_radius_over_tls_server(
    config: RadiusTlsServerConfig,
    shutdown: tokio::sync::oneshot::Receiver<()>,
) -> QidResult<()> {
    if config.shared_secret.is_empty() {
        return Err(QidError::Config {
            message: "RADIUS/TLS shared secret is required".to_string(),
        });
    }
    let listener = TcpListener::bind(&config.bind_address)
        .await
        .map_err(|error| QidError::Internal {
            message: format!("RADIUS/TLS bind failed: {error}"),
        })?;
    run_radius_over_tls_server_with_listener(config, listener, shutdown).await
}

#[cfg(feature = "radius-tls")]
pub async fn run_radius_over_tls_server_with_listener(
    config: RadiusTlsServerConfig,
    listener: TcpListener,
    mut shutdown: tokio::sync::oneshot::Receiver<()>,
) -> QidResult<()> {
    if config.shared_secret.is_empty() {
        return Err(QidError::Config {
            message: "RADIUS/TLS shared secret is required".to_string(),
        });
    }
    let acceptor = TlsAcceptor::from(Arc::new(build_radius_tls_server_config(&config)?));
    loop {
        tokio::select! {
            biased;
            _ = &mut shutdown => return Ok(()),
            accepted = listener.accept() => {
                let (tcp, peer) = match accepted {
                    Ok(accepted) => accepted,
                    Err(error) => {
                        tracing::warn!(error = %error, "RADIUS/TLS accept failed");
                        continue;
                    }
                };
                let acceptor = acceptor.clone();
                let shared_secret = config.shared_secret.clone();
                tokio::spawn(async move {
                    if let Err(error) = handle_radius_tls_connection(acceptor, tcp, shared_secret).await {
                        tracing::warn!(peer = %peer, error = %error, "RADIUS/TLS connection failed");
                    }
                });
            }
        }
    }
}

#[cfg(feature = "radius-tls")]
pub fn validate_radius_tls_server_config(config: &RadiusTlsServerConfig) -> QidResult<()> {
    let _ = build_radius_tls_server_config(config)?;
    Ok(())
}

#[cfg(feature = "radius-tls")]
async fn handle_radius_tls_connection(
    acceptor: TlsAcceptor,
    tcp: TcpStream,
    shared_secret: Vec<u8>,
) -> QidResult<()> {
    let mut stream = acceptor
        .accept(tcp)
        .await
        .map_err(|error| QidError::Unauthorized {
            message: format!("RADIUS/TLS handshake failed: {error}"),
        })?;
    loop {
        let mut header = [0u8; 4];
        match stream.read_exact(&mut header).await {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(error) => {
                return Err(QidError::Internal {
                    message: format!("RADIUS/TLS request header read failed: {error}"),
                });
            }
        }
        let length = u16::from_be_bytes([header[2], header[3]]) as usize;
        if !(20..=4096).contains(&length) {
            return Err(QidError::BadRequest {
                message: "RADIUS/TLS packet length is invalid".to_string(),
            });
        }
        let mut packet = vec![0u8; length];
        packet[..4].copy_from_slice(&header);
        stream
            .read_exact(&mut packet[4..])
            .await
            .map_err(|error| QidError::Internal {
                message: format!("RADIUS/TLS request body read failed: {error}"),
            })?;
        let response = crate::server::handle_radius_access_request_bytes(&packet, &shared_secret)?;
        stream
            .write_all(&response)
            .await
            .map_err(|error| QidError::Internal {
                message: format!("RADIUS/TLS response write failed: {error}"),
            })?;
    }
}

#[cfg(feature = "radius-tls")]
fn build_radius_tls_server_config(
    config: &RadiusTlsServerConfig,
) -> QidResult<rustls::ServerConfig> {
    if config.certificate_der.is_empty() || config.private_key_der.is_empty() {
        return Err(QidError::Config {
            message: "RADIUS/TLS certificate and private key are required".to_string(),
        });
    }
    let cert_chain = parse_certificate_chain(&config.certificate_der)?;
    let private_key = parse_private_key(&config.private_key_der)?;
    let builder = rustls::ServerConfig::builder();
    let server_config = if let Some(client_ca) = config.client_ca_certificate_der.as_ref() {
        let mut roots = rustls::RootCertStore::empty();
        for certificate in parse_certificate_chain(client_ca)? {
            roots
                .add(certificate)
                .map_err(|error| QidError::BadRequest {
                    message: format!("RADIUS/TLS client CA certificate is invalid: {error}"),
                })?;
        }
        let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
            .build()
            .map_err(|error| QidError::BadRequest {
                message: format!("RADIUS/TLS client verifier is invalid: {error}"),
            })?;
        builder
            .with_client_cert_verifier(verifier)
            .with_single_cert(cert_chain, private_key)
    } else {
        builder
            .with_no_client_auth()
            .with_single_cert(cert_chain, private_key)
    }
    .map_err(|error| QidError::BadRequest {
        message: format!("RADIUS/TLS certificate chain is invalid: {error}"),
    })?;
    Ok(server_config)
}

#[cfg(feature = "radius-tls")]
fn parse_certificate_chain(
    mut certificate_der: &[u8],
) -> QidResult<Vec<rustls_pki_types::CertificateDer<'static>>> {
    if certificate_der.starts_with(b"-----BEGIN ") {
        let certs = rustls_pemfile::certs(&mut certificate_der)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| QidError::BadRequest {
                message: format!("RADIUS/TLS certificate PEM is invalid: {error}"),
            })?;
        if certs.is_empty() {
            return Err(QidError::BadRequest {
                message: "RADIUS/TLS certificate PEM does not contain a certificate".to_string(),
            });
        }
        Ok(certs)
    } else {
        Ok(vec![rustls_pki_types::CertificateDer::from(
            certificate_der.to_vec(),
        )])
    }
}

#[cfg(feature = "radius-tls")]
fn parse_private_key(
    mut private_key_der: &[u8],
) -> QidResult<rustls_pki_types::PrivateKeyDer<'static>> {
    if private_key_der.starts_with(b"-----BEGIN ") {
        let mut keys = rustls_pemfile::private_key(&mut private_key_der).map_err(|error| {
            QidError::BadRequest {
                message: format!("RADIUS/TLS private key PEM is invalid: {error}"),
            }
        })?;
        keys.take().ok_or_else(|| QidError::BadRequest {
            message: "RADIUS/TLS private key PEM does not contain a private key".to_string(),
        })
    } else {
        rustls_pki_types::PrivateKeyDer::try_from(private_key_der.to_vec()).map_err(|error| {
            QidError::BadRequest {
                message: format!("RADIUS/TLS private key is invalid: {error}"),
            }
        })
    }
}

pub struct RadiusDtlsConfig {
    pub server_address: String,
    pub server_port: u16,
    pub certificate_der: Vec<u8>,
    pub private_key_der: Vec<u8>,
}

#[cfg(feature = "radius-tls")]
fn validate_radius_packet_length(packet: &[u8]) -> QidResult<()> {
    if packet.len() < 20 {
        return Err(QidError::BadRequest {
            message: "RADIUS packet is shorter than 20 bytes".to_string(),
        });
    }
    let declared = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    if declared != packet.len() {
        return Err(QidError::BadRequest {
            message: "RADIUS packet length does not match the encoded length".to_string(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn radius_tls_config_construct() {
        let config = RadiusTlsConfig {
            server_address: "127.0.0.1".to_string(),
            server_port: 2083,
            certificate_der: vec![0x00],
            private_key_der: vec![0x00],
            ca_certificate_der: None,
        };
        assert_eq!(config.server_port, 2083);
    }

    #[test]
    fn radius_dtls_config_construct() {
        let config = RadiusDtlsConfig {
            server_address: "127.0.0.1".to_string(),
            server_port: 2083,
            certificate_der: vec![0x00],
            private_key_der: vec![0x00],
        };
        assert_eq!(config.server_port, 2083);
    }
}
