use anyhow::{Context, bail};
use axum::http::Request;
use axum_server::{accept::Accept, tls_rustls::RustlsAcceptor};
use qid_core::{config::TlsConfig, util::base64_url_encode};
use rustls_pki_types::{CertificateDer, CertificateRevocationListDer, PrivateKeyDer};
use sha2::{Digest, Sha256};
use std::{future::Future, io, pin::Pin, sync::Arc};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::server::TlsStream;
use tower::Service;

#[derive(Clone, Debug)]
pub struct NativeTlsPeer {
    pub leaf_x5t_s256: String,
}

#[derive(Clone, Debug)]
pub struct NativeMtlsAcceptor<A = axum_server::accept::DefaultAcceptor> {
    inner: RustlsAcceptor<A>,
}

impl NativeMtlsAcceptor {
    pub fn new(inner: RustlsAcceptor) -> Self {
        Self { inner }
    }
}

impl<I, S, A> Accept<I, S> for NativeMtlsAcceptor<A>
where
    A: Accept<I, S> + Clone + Send + 'static,
    A::Stream: AsyncRead + AsyncWrite + Unpin + Send,
    A::Service: Send,
    A::Future: Send,
    I: Send + 'static,
    S: Send + 'static,
{
    type Stream = TlsStream<A::Stream>;
    type Service = NativeTlsPeerService<A::Service>;
    type Future = Pin<Box<dyn Future<Output = io::Result<(Self::Stream, Self::Service)>> + Send>>;

    fn accept(&self, stream: I, service: S) -> Self::Future {
        let inner = self.inner.clone();
        Box::pin(async move {
            let (tls_stream, service) = inner.accept(stream, service).await?;
            let peer = tls_stream
                .get_ref()
                .1
                .peer_certificates()
                .and_then(|certificates| certificates.first())
                .map(|certificate| NativeTlsPeer {
                    leaf_x5t_s256: base64_url_encode(&Sha256::digest(certificate.as_ref())),
                });
            Ok((
                tls_stream,
                NativeTlsPeerService {
                    inner: service,
                    peer,
                },
            ))
        })
    }
}

#[derive(Clone, Debug)]
pub struct NativeTlsPeerService<S> {
    inner: S,
    peer: Option<NativeTlsPeer>,
}

impl<S, B> Service<Request<B>> for NativeTlsPeerService<S>
where
    S: Service<Request<B>>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = S::Future;

    fn poll_ready(
        &mut self,
        context: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(context)
    }

    fn call(&mut self, mut request: Request<B>) -> Self::Future {
        if let Some(peer) = &self.peer {
            request.extensions_mut().insert(peer.clone());
        }
        self.inner.call(request)
    }
}

pub fn load_rustls_config(
    config: &TlsConfig,
) -> anyhow::Result<axum_server::tls_rustls::RustlsConfig> {
    let certificates = read_certificates(&config.cert, "server certificate")?;
    let private_key = read_private_key(&config.key)?;

    let builder = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .context("failed to select safe TLS protocol versions")?;
    let builder = if let Some(client_ca) = &config.client_ca {
        let mut roots = rustls::RootCertStore::empty();
        for certificate in read_certificates(client_ca, "client CA certificate")? {
            roots
                .add(certificate)
                .context("client CA certificate is not a valid trust anchor")?;
        }
        if roots.is_empty() {
            bail!("client CA bundle contains no trust anchors");
        }
        let mut verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
            Arc::new(roots),
            Arc::new(rustls::crypto::aws_lc_rs::default_provider()),
        );
        if !config.client_crls.is_empty() {
            let mut crls = Vec::new();
            for path in &config.client_crls {
                crls.extend(read_crls(path)?);
            }
            verifier = verifier.with_crls(crls);
        }
        builder.with_client_cert_verifier(
            verifier
                .allow_unauthenticated()
                .build()
                .context("failed to build client certificate path verifier")?,
        )
    } else {
        builder.with_no_client_auth()
    };

    let mut server_config = if !config.ocsp_responses.is_empty() {
        if config.ocsp_responses.len() > certificates.len() {
            bail!(
                "OCSP response list has {} entries but certificate chain has {} certificates",
                config.ocsp_responses.len(),
                certificates.len()
            );
        }
        let mut responses = Vec::with_capacity(config.ocsp_responses.len());
        for path in &config.ocsp_responses {
            let Some(path) = path else {
                responses.push(Vec::new());
                continue;
            };
            let response = std::fs::read(path)
                .with_context(|| format!("failed to read OCSP response {path}"))?;
            if response.is_empty() {
                bail!("OCSP response must not be empty: {path}");
            }
            responses.push(response);
        }
        builder
            .with_single_cert_with_ocsp_multi(certificates, private_key, responses)
            .context(
                "server certificate chain, private key, or RFC 6961 OCSP responses are invalid",
            )?
    } else {
        builder
            .with_single_cert(certificates, private_key)
            .context("server certificate chain or private key is invalid")?
    };
    server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(axum_server::tls_rustls::RustlsConfig::from_config(
        Arc::new(server_config),
    ))
}

fn read_certificates(path: &str, label: &str) -> anyhow::Result<Vec<CertificateDer<'static>>> {
    let bytes = std::fs::read(path).with_context(|| format!("failed to read {label} {path}"))?;
    let mut input = bytes.as_slice();
    let certificates = rustls_pemfile::certs(&mut input)
        .collect::<Result<Vec<_>, _>>()
        .with_context(|| format!("failed to parse {label} PEM {path}"))?;
    if certificates.is_empty() {
        bail!("{label} PEM contains no certificates: {path}");
    }
    Ok(certificates)
}

fn read_private_key(path: &str) -> anyhow::Result<PrivateKeyDer<'static>> {
    let bytes =
        std::fs::read(path).with_context(|| format!("failed to read server private key {path}"))?;
    rustls_pemfile::private_key(&mut bytes.as_slice())
        .with_context(|| format!("failed to parse server private key PEM {path}"))?
        .with_context(|| format!("server private key PEM contains no key: {path}"))
}

fn read_crls(path: &str) -> anyhow::Result<Vec<CertificateRevocationListDer<'static>>> {
    let bytes = std::fs::read(path).with_context(|| format!("failed to read client CRL {path}"))?;
    if bytes.starts_with(b"-----BEGIN ") {
        let mut input = bytes.as_slice();
        let crls = rustls_pemfile::crls(&mut input)
            .collect::<Result<Vec<_>, _>>()
            .with_context(|| format!("failed to parse client CRL PEM {path}"))?;
        if crls.is_empty() {
            bail!("client CRL PEM contains no CRLs: {path}");
        }
        Ok(crls)
    } else if bytes.is_empty() {
        bail!("client CRL must not be empty: {path}");
    } else {
        Ok(vec![CertificateRevocationListDer::from(bytes)])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{
        BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType,
        ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose, PKCS_ECDSA_P256_SHA256,
    };
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
    use std::io::Cursor;

    #[test]
    fn configured_client_ca_accepts_trusted_and_rejects_untrusted_client() {
        let (ca, ca_key) = certificate_authority("trusted CA");
        let (server, server_key) = signed_certificate(
            "localhost",
            ExtendedKeyUsagePurpose::ServerAuth,
            &ca,
            &ca_key,
        );
        let (trusted_client, trusted_client_key) = signed_certificate(
            "trusted-client.example",
            ExtendedKeyUsagePurpose::ClientAuth,
            &ca,
            &ca_key,
        );
        let (other_ca, other_ca_key) = certificate_authority("other CA");
        let (untrusted_client, untrusted_client_key) = signed_certificate(
            "untrusted-client.example",
            ExtendedKeyUsagePurpose::ClientAuth,
            &other_ca,
            &other_ca_key,
        );

        let directory = tempfile::tempdir().expect("temporary directory");
        let server_cert_path = directory.path().join("server.pem");
        let server_key_path = directory.path().join("server-key.pem");
        let client_ca_path = directory.path().join("client-ca.pem");
        std::fs::write(&server_cert_path, server.pem()).expect("write server certificate");
        std::fs::write(&server_key_path, server_key.serialize_pem()).expect("write server key");
        std::fs::write(&client_ca_path, ca.pem()).expect("write client CA");
        let config = TlsConfig {
            cert: server_cert_path.to_string_lossy().into_owned(),
            key: server_key_path.to_string_lossy().into_owned(),
            client_ca: Some(client_ca_path.to_string_lossy().into_owned()),
            client_crls: Vec::new(),
            ocsp_responses: Vec::new(),
        };
        let server_config = load_rustls_config(&config)
            .expect("load TLS configuration")
            .get_inner();

        let trusted_config = client_config(&ca, &trusted_client, &trusted_client_key);
        assert!(drive_handshake(server_config.clone(), trusted_config).is_ok());

        let untrusted_config = client_config(&ca, &untrusted_client, &untrusted_client_key);
        assert!(drive_handshake(server_config, untrusted_config).is_err());
    }

    #[test]
    fn client_certificate_path_requires_the_presented_intermediate() {
        let (root, root_key) = certificate_authority("path root CA");
        let (intermediate, intermediate_key) =
            intermediate_certificate_authority("path intermediate CA", &root, &root_key);
        let (server, server_key) = signed_certificate(
            "localhost",
            ExtendedKeyUsagePurpose::ServerAuth,
            &root,
            &root_key,
        );
        let (client, client_key) = signed_certificate(
            "path-client.example",
            ExtendedKeyUsagePurpose::ClientAuth,
            &intermediate,
            &intermediate_key,
        );

        let directory = tempfile::tempdir().expect("temporary directory");
        let server_cert_path = directory.path().join("server.pem");
        let server_key_path = directory.path().join("server-key.pem");
        let client_ca_path = directory.path().join("client-root-ca.pem");
        std::fs::write(&server_cert_path, server.pem()).expect("write server certificate");
        std::fs::write(&server_key_path, server_key.serialize_pem()).expect("write server key");
        std::fs::write(&client_ca_path, root.pem()).expect("write client root CA");
        let config = TlsConfig {
            cert: server_cert_path.to_string_lossy().into_owned(),
            key: server_key_path.to_string_lossy().into_owned(),
            client_ca: Some(client_ca_path.to_string_lossy().into_owned()),
            client_crls: Vec::new(),
            ocsp_responses: Vec::new(),
        };
        let server_config = load_rustls_config(&config)
            .expect("load TLS configuration")
            .get_inner();

        let complete_chain = client_config_with_chain(
            &root,
            vec![client.der().clone(), intermediate.der().clone()],
            &client_key,
        );
        assert!(drive_handshake(server_config.clone(), complete_chain).is_ok());

        let missing_intermediate =
            client_config_with_chain(&root, vec![client.der().clone()], &client_key);
        assert!(drive_handshake(server_config, missing_intermediate).is_err());
    }

    #[test]
    fn ocsp_response_list_cannot_exceed_server_certificate_chain() {
        let (ca, ca_key) = certificate_authority("OCSP test CA");
        let (server, server_key) = signed_certificate(
            "localhost",
            ExtendedKeyUsagePurpose::ServerAuth,
            &ca,
            &ca_key,
        );

        let directory = tempfile::tempdir().expect("temporary directory");
        let server_cert_path = directory.path().join("server.pem");
        let server_key_path = directory.path().join("server-key.pem");
        let first_ocsp_path = directory.path().join("leaf.ocsp.der");
        let second_ocsp_path = directory.path().join("extra.ocsp.der");
        std::fs::write(&server_cert_path, server.pem()).expect("write server certificate");
        std::fs::write(&server_key_path, server_key.serialize_pem()).expect("write server key");
        std::fs::write(&first_ocsp_path, [0x30, 0x00]).expect("write leaf OCSP response");
        std::fs::write(&second_ocsp_path, [0x30, 0x00]).expect("write extra OCSP response");

        let config = TlsConfig {
            cert: server_cert_path.to_string_lossy().into_owned(),
            key: server_key_path.to_string_lossy().into_owned(),
            client_ca: None,
            client_crls: Vec::new(),
            ocsp_responses: vec![
                Some(first_ocsp_path.to_string_lossy().into_owned()),
                Some(second_ocsp_path.to_string_lossy().into_owned()),
            ],
        };

        let error = load_rustls_config(&config).expect_err("oversized response list must fail");
        assert!(
            error
                .to_string()
                .contains("2 entries but certificate chain has 1 certificates")
        );
    }

    fn certificate_authority(name: &str) -> (Certificate, KeyPair) {
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("generate CA key");
        let mut params = CertificateParams::default();
        let mut distinguished_name = DistinguishedName::new();
        distinguished_name.push(DnType::CommonName, name);
        params.distinguished_name = distinguished_name;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let certificate = params.self_signed(&key).expect("generate CA certificate");
        (certificate, key)
    }

    fn intermediate_certificate_authority(
        name: &str,
        issuer: &Certificate,
        issuer_key: &KeyPair,
    ) -> (Certificate, KeyPair) {
        let key =
            KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("generate intermediate CA key");
        let mut params = CertificateParams::default();
        let mut distinguished_name = DistinguishedName::new();
        distinguished_name.push(DnType::CommonName, name);
        params.distinguished_name = distinguished_name;
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let certificate = params
            .signed_by(&key, issuer, issuer_key)
            .expect("generate intermediate CA certificate");
        (certificate, key)
    }

    fn signed_certificate(
        name: &str,
        usage: ExtendedKeyUsagePurpose,
        issuer: &Certificate,
        issuer_key: &KeyPair,
    ) -> (Certificate, KeyPair) {
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("generate leaf key");
        let mut params = CertificateParams::new(vec![name.to_string()])
            .expect("build leaf certificate parameters");
        params.extended_key_usages = vec![usage];
        let certificate = params
            .signed_by(&key, issuer, issuer_key)
            .expect("generate signed leaf certificate");
        (certificate, key)
    }

    fn client_config(
        server_ca: &Certificate,
        client: &Certificate,
        client_key: &KeyPair,
    ) -> Arc<rustls::ClientConfig> {
        client_config_with_chain(server_ca, vec![client.der().clone()], client_key)
    }

    fn client_config_with_chain(
        server_ca: &Certificate,
        client_chain: Vec<CertificateDer<'static>>,
        client_key: &KeyPair,
    ) -> Arc<rustls::ClientConfig> {
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(server_ca.der().clone())
            .expect("add server CA trust anchor");
        Arc::new(
            rustls::ClientConfig::builder_with_provider(Arc::new(
                rustls::crypto::aws_lc_rs::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .expect("select safe TLS protocol versions")
            .with_root_certificates(roots)
            .with_client_auth_cert(
                client_chain,
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(client_key.serialize_der())),
            )
            .expect("build client TLS configuration"),
        )
    }

    fn drive_handshake(
        server_config: Arc<rustls::ServerConfig>,
        client_config: Arc<rustls::ClientConfig>,
    ) -> anyhow::Result<()> {
        let mut server = rustls::ServerConnection::new(server_config)?;
        let server_name = ServerName::try_from("localhost")?.to_owned();
        let mut client = rustls::ClientConnection::new(client_config, server_name)?;

        for _ in 0..20 {
            transfer_client_to_server(&mut client, &mut server)?;
            transfer_server_to_client(&mut server, &mut client)?;
            if !client.is_handshaking() && !server.is_handshaking() {
                return Ok(());
            }
        }
        bail!("TLS handshake did not complete")
    }

    fn transfer_client_to_server(
        client: &mut rustls::ClientConnection,
        server: &mut rustls::ServerConnection,
    ) -> anyhow::Result<()> {
        let mut wire = Vec::new();
        client.write_tls(&mut wire)?;
        if !wire.is_empty() {
            server.read_tls(&mut Cursor::new(wire))?;
            server.process_new_packets()?;
        }
        Ok(())
    }

    fn transfer_server_to_client(
        server: &mut rustls::ServerConnection,
        client: &mut rustls::ClientConnection,
    ) -> anyhow::Result<()> {
        let mut wire = Vec::new();
        server.write_tls(&mut wire)?;
        if !wire.is_empty() {
            client.read_tls(&mut Cursor::new(wire))?;
            client.process_new_packets()?;
        }
        Ok(())
    }
}
