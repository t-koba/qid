use anyhow::{Context, bail};
use axum::Router;
use axum_server::accept::Accept;
use p256::{SecretKey, ecdsa::SigningKey, pkcs8::DecodePrivateKey};
use qid_core::config::TlsConfig;
use qid_tls::tls12::{
    ALERT, APPLICATION_DATA, CHANGE_CIPHER_SPEC, HANDSHAKE, OcspResponse, RecordProtector,
    ServerHandshake, ServerHandshakeConfig, ServerHandshakeState, Tls12Error,
};
use rand::{RngCore, rngs::OsRng};
use std::{
    future::Future,
    io,
    pin::Pin,
    sync::Arc,
    task::{Context as TaskContext, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::TcpListener,
};
use tracing::info;

// RFC 5246 §6.2.1 and §6.2.3.3: a fragment is at most 2^14 bytes and a
// protected record body at most 2^14 + 2048 bytes. These are protocol limits,
// not deployment policy.
const HEADER_LEN: usize = 5;
const MAX_FRAGMENT: usize = 1 << 14;
const MAX_CIPHERTEXT: usize = MAX_FRAGMENT + 2048;
// Bound one poll_write's pending protected records; callers can write again.
const MAX_PENDING_OUTBOUND: usize = MAX_FRAGMENT * 8;
const READ_CHUNK: usize = 8192;

/// The daemon calls the guard before reading configuration. Configuration
/// validation, including unsupported client-certificate policy, happens in
/// `serve_https` where the `TlsConfig` is available.
pub(super) fn startup_guard() -> anyhow::Result<()> {
    Ok(())
}

pub(super) async fn serve_https(
    config: &TlsConfig,
    listener: TcpListener,
    app: Router,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> anyhow::Result<()> {
    let config = Arc::new(load_server_config(config).context("failed to load TLS configuration")?);
    let acceptor = QidAcceptor::new(config);
    let std_listener = listener.into_std().context("failed to convert listener")?;
    let handle = axum_server::Handle::new();
    let shutdown_handle = handle.clone();
    tokio::spawn(async move {
        shutdown.await;
        info!(target: "qidd", "initiating graceful shutdown (TLS)");
        shutdown_handle.graceful_shutdown(Some(std::time::Duration::from_secs(30)));
    });
    info!(target: "qidd", tls = true, backend = "qid-tls12", "listening with TLS");
    axum_server::from_tcp(std_listener)
        .acceptor(acceptor)
        .handle(handle)
        .serve(app.into_make_service())
        .await
        .map_err(|e| qid_core::error::QidError::Internal {
            message: format!("server error: {e}"),
        })?;
    Ok(())
}

struct ServerConfig {
    certificates: Vec<Vec<u8>>,
    ocsp_responses: Vec<Option<Vec<u8>>>,
    signing_key: SigningKey,
}

fn load_server_config(config: &TlsConfig) -> anyhow::Result<ServerConfig> {
    if config.client_ca.is_some() {
        bail!(
            "tls-qid TLS 1.2 backend does not request or authenticate client certificates: client_ca is unsupported"
        );
    }
    if !config.client_crls.is_empty() {
        bail!(
            "tls-qid TLS 1.2 backend does not request or authenticate client certificates: client_crls is unsupported"
        );
    }
    let certificates = read_certificates(&config.cert)?;
    let signing_key = read_signing_key(&config.key)?;
    let ocsp_responses = read_ocsp_responses(&config.ocsp_responses, certificates.len())?;
    Ok(ServerConfig {
        certificates,
        ocsp_responses,
        signing_key,
    })
}

fn read_certificates(path: &str) -> anyhow::Result<Vec<Vec<u8>>> {
    let bytes =
        std::fs::read(path).with_context(|| format!("failed to read server certificate {path}"))?;
    let certificates = rustls_pemfile::certs(&mut bytes.as_slice())
        .collect::<Result<Vec<_>, _>>()
        .with_context(|| format!("failed to parse server certificate PEM {path}"))?;
    if certificates.is_empty() {
        bail!("server certificate PEM contains no certificates: {path}");
    }
    Ok(certificates
        .into_iter()
        .map(|der| der.as_ref().to_vec())
        .collect())
}

fn read_signing_key(path: &str) -> anyhow::Result<SigningKey> {
    let pem = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read server key {path}"))?;
    let secret = SecretKey::from_pkcs8_pem(&pem)
        .with_context(|| format!("server key {path} is not a PKCS8 EC private key"))?;
    Ok(SigningKey::from(secret))
}

fn read_ocsp_responses(
    entries: &[Option<String>],
    chain_len: usize,
) -> anyhow::Result<Vec<Option<Vec<u8>>>> {
    if entries.len() > chain_len {
        bail!(
            "OCSP response list has {} entries but certificate chain has {chain_len} certificates",
            entries.len()
        );
    }
    entries
        .iter()
        .map(|entry| match entry {
            None => Ok(None),
            Some(path) => {
                let der = std::fs::read(path)
                    .with_context(|| format!("failed to read OCSP response {path}"))?;
                if der.is_empty() {
                    bail!("OCSP response must not be empty: {path}");
                }
                Ok(Some(der))
            }
        })
        .collect()
}

/// Draw an ECDHE scalar from the OS RNG. A 32-byte draw that is not a valid
/// scalar (an astronomically rare event for P-256) is simply drawn again.
fn fresh_ecdhe_secret() -> SecretKey {
    let mut bytes = zeroize::Zeroizing::new([0u8; 32]);
    loop {
        OsRng.fill_bytes(&mut *bytes);
        if let Ok(secret) = SecretKey::from_slice(&*bytes) {
            return secret;
        }
    }
}

#[derive(Clone)]
struct QidAcceptor {
    config: Arc<ServerConfig>,
}

impl QidAcceptor {
    fn new(config: Arc<ServerConfig>) -> Self {
        Self { config }
    }
}

impl<I, S> Accept<I, S> for QidAcceptor
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    S: Send + 'static,
{
    type Stream = QidTlsStream<I>;
    type Service = S;
    type Future = Pin<Box<dyn Future<Output = io::Result<(Self::Stream, Self::Service)>> + Send>>;

    fn accept(&self, mut stream: I, service: S) -> Self::Future {
        let config = Arc::clone(&self.config);
        Box::pin(async move {
            let (protector, pending) = server_handshake(&mut stream, &config).await?;
            Ok((QidTlsStream::new(stream, protector, pending), service))
        })
    }
}

/// Perform one qid-tls TLS 1.2 handshake, feeding the byte-in/byte-out driver
/// exactly one record at a time. This keeps any application records coalesced
/// after the client Finished out of the driver, which intentionally discards
/// bytes left over once it completes.
async fn server_handshake<S>(
    io: &mut S,
    config: &ServerConfig,
) -> io::Result<(RecordProtector, Vec<u8>)>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let ecdhe_secret = fresh_ecdhe_secret();
    let mut server_random = [0u8; 32];
    OsRng.fill_bytes(&mut server_random);
    let certificates: Vec<&[u8]> = config.certificates.iter().map(Vec::as_slice).collect();
    let ocsp_responses: Vec<OcspResponse<'_>> = config
        .ocsp_responses
        .iter()
        .map(|entry| match entry {
            Some(der) => OcspResponse::Der(der),
            None => OcspResponse::Missing,
        })
        .collect();
    let mut handshake = ServerHandshake::new(ServerHandshakeConfig {
        certificates: &certificates,
        ocsp_responses: &ocsp_responses,
        signing_key: &config.signing_key,
        ecdhe_secret: &ecdhe_secret,
        server_random,
    });

    let mut buffer = Vec::new();
    let mut chunk = [0u8; READ_CHUNK];
    while *handshake.state() != ServerHandshakeState::Complete {
        while let Some(len) = record_len(&buffer)? {
            let record = buffer[..len].to_vec();
            buffer.drain(..len);
            let output = handshake.push(&record).map_err(protocol_failure)?;
            if !output.is_empty() {
                io.write_all(&output).await?;
            }
        }
        if *handshake.state() == ServerHandshakeState::Complete {
            break;
        }
        let count = io.read(&mut chunk).await?;
        if count == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "TLS 1.2 handshake closed before completion",
            ));
        }
        buffer.extend_from_slice(&chunk[..count]);
    }
    io.flush().await?;
    let protector = handshake
        .into_record_protector()
        .map_err(protocol_failure)?;
    Ok((protector, buffer))
}

/// A protected TLS 1.2 application-data stream over an accepted socket.
struct QidTlsStream<S> {
    io: S,
    protector: RecordProtector,
    read_buffer: Vec<u8>,
    plaintext: Vec<u8>,
    plaintext_at: usize,
    outbound: Vec<u8>,
    outbound_at: usize,
    eof: bool,
    close_notify_sent: bool,
}

impl<S> QidTlsStream<S> {
    fn new(io: S, protector: RecordProtector, pending: Vec<u8>) -> Self {
        Self {
            io,
            protector,
            read_buffer: pending,
            plaintext: Vec::new(),
            plaintext_at: 0,
            outbound: Vec::new(),
            outbound_at: 0,
            eof: false,
            close_notify_sent: false,
        }
    }
}

/// Length of one complete TLS record, or `None` when more bytes are needed.
/// Only header validity and the protocol length bound are checked here: the
/// protector authenticates protected records, and the handshake driver
/// validates plaintext handshake records.
fn record_len(buffer: &[u8]) -> io::Result<Option<usize>> {
    if buffer.len() < HEADER_LEN {
        return Ok(None);
    }
    if !matches!(
        buffer[0],
        CHANGE_CIPHER_SPEC | ALERT | HANDSHAKE | APPLICATION_DATA
    ) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid TLS record content type",
        ));
    }
    let length = usize::from(u16::from_be_bytes([buffer[3], buffer[4]]));
    if length == 0 || length > MAX_CIPHERTEXT {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid TLS record length",
        ));
    }
    Ok((buffer.len() >= HEADER_LEN + length).then_some(HEADER_LEN + length))
}

fn protocol_failure(error: Tls12Error) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("TLS 1.2 protocol failure: {error}"),
    )
}

impl<S> QidTlsStream<S>
where
    S: AsyncWrite + Unpin,
{
    fn flush_pending(&mut self, context: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        while self.outbound_at < self.outbound.len() {
            match Pin::new(&mut self.io).poll_write(context, &self.outbound[self.outbound_at..]) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "TLS transport accepted no record bytes",
                    )));
                }
                Poll::Ready(Ok(count)) => self.outbound_at += count,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            }
        }
        self.outbound.clear();
        self.outbound_at = 0;
        Poll::Ready(Ok(()))
    }
}

impl<S> AsyncRead for QidTlsStream<S>
where
    S: AsyncRead + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut TaskContext<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if output.remaining() == 0 || this.eof {
            return Poll::Ready(Ok(()));
        }
        let mut chunk = [0u8; READ_CHUNK];
        loop {
            if this.plaintext_at < this.plaintext.len() {
                let count = output
                    .remaining()
                    .min(this.plaintext.len() - this.plaintext_at);
                let end = this.plaintext_at + count;
                output.put_slice(&this.plaintext[this.plaintext_at..end]);
                this.plaintext_at = end;
                if this.plaintext_at == this.plaintext.len() {
                    this.plaintext.clear();
                    this.plaintext_at = 0;
                }
                return Poll::Ready(Ok(()));
            }
            let len = match record_len(&this.read_buffer) {
                Ok(Some(len)) => len,
                Ok(None) => {
                    let mut incoming = ReadBuf::new(&mut chunk);
                    match Pin::new(&mut this.io).poll_read(context, &mut incoming) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Ok(())) if incoming.filled().is_empty() => {
                            this.eof = true;
                            return Poll::Ready(Ok(()));
                        }
                        Poll::Ready(Ok(())) => {
                            this.read_buffer.extend_from_slice(incoming.filled());
                            continue;
                        }
                        Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    }
                }
                Err(error) => return Poll::Ready(Err(error)),
            };
            let record = this.read_buffer[..len].to_vec();
            this.read_buffer.drain(..len);
            let (content_type, plaintext) = match this.protector.open(&record) {
                Ok(result) => result,
                Err(error) => return Poll::Ready(Err(protocol_failure(error))),
            };
            match content_type {
                APPLICATION_DATA => {
                    if !plaintext.is_empty() {
                        this.plaintext = plaintext;
                        this.plaintext_at = 0;
                    }
                }
                ALERT if plaintext.first() == Some(&1) && plaintext.get(1) == Some(&0) => {
                    this.eof = true;
                    return Poll::Ready(Ok(()));
                }
                ALERT => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        "TLS alert received after handshake",
                    )));
                }
                _ => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "unexpected TLS record type after handshake",
                    )));
                }
            }
        }
    }
}

impl<S> AsyncWrite for QidTlsStream<S>
where
    S: AsyncWrite + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut TaskContext<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let this = self.get_mut();
        if this.close_notify_sent {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "TLS connection is closing",
            )));
        }
        match this.flush_pending(context) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) => {}
        }
        let mut written = 0;
        for fragment in data.chunks(MAX_FRAGMENT) {
            let record = match this.protector.protect(APPLICATION_DATA, fragment) {
                Ok(record) => record,
                Err(error) => return Poll::Ready(Err(protocol_failure(error))),
            };
            if this.outbound.len() + record.len() > MAX_PENDING_OUTBOUND {
                break;
            }
            this.outbound.extend_from_slice(&record);
            written += fragment.len();
        }
        if written == 0 {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "TLS application record exceeds the pending write bound",
            )));
        }
        match this.flush_pending(context) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) => Poll::Ready(Ok(written)),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, context: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match this.flush_pending(context) {
            Poll::Ready(Ok(())) => Pin::new(&mut this.io).poll_flush(context),
            other => other,
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, context: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match this.flush_pending(context) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) => {}
        }
        if !this.close_notify_sent {
            let alert = match this.protector.protect(ALERT, &[1, 0]) {
                Ok(alert) => alert,
                Err(error) => return Poll::Ready(Err(protocol_failure(error))),
            };
            this.outbound.extend_from_slice(&alert);
            this.close_notify_sent = true;
        }
        match this.flush_pending(context) {
            Poll::Ready(Ok(())) => Pin::new(&mut this.io).poll_shutdown(context),
            other => other,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::routing::get;
    use rcgen::{
        BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType,
        ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose, PKCS_ECDSA_P256_SHA256,
    };
    use rustls::ClientConfig;
    use rustls_pki_types::ServerName;
    use std::{
        io::{BufRead, BufReader, Write},
        net::Ipv4Addr,
        process::{Command, Stdio},
        time::Duration,
    };
    use tokio::{io::AsyncReadExt, net::TcpStream};
    use tokio_rustls::TlsConnector;

    // Opaque test bytes: the listener staples them verbatim, it does not parse them.
    const STAPLE_A: &[u8] = b"qid-test: leaf OCSP staple\x00\xff";
    const STAPLE_B: &[u8] = b"qid-test: intermediate OCSP staple";

    // Valid DER OCSPResponse values with distinct responseStatus codes. The
    // Bouncy Castle client parses them without validating their status during
    // the handshake.
    const BC_STAPLE_A: &[u8] = &[0x30, 0x03, 0x0A, 0x01, 0x00];
    const BC_STAPLE_B: &[u8] = &[0x30, 0x03, 0x0A, 0x01, 0x03];

    struct Fixture {
        config: TlsConfig,
        ca: Certificate,
        directory: tempfile::TempDir,
    }

    fn fixture() -> Fixture {
        let ca_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("generate CA key");
        let mut ca_params = CertificateParams::default();
        let mut ca_name = DistinguishedName::new();
        ca_name.push(DnType::CommonName, "qid TLS 1.2 backend test CA");
        ca_params.distinguished_name = ca_name;
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        let ca = ca_params.self_signed(&ca_key).expect("generate test CA");

        let leaf_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("generate leaf key");
        let mut leaf_params =
            CertificateParams::new(vec!["localhost".to_owned()]).expect("leaf parameters");
        leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let leaf = leaf_params
            .signed_by(&leaf_key, &ca, &ca_key)
            .expect("sign test leaf");

        let directory = tempfile::tempdir().expect("temporary directory");
        let cert_path = directory.path().join("leaf.pem");
        let key_path = directory.path().join("leaf.key.pem");
        std::fs::write(&cert_path, leaf.pem()).expect("write server certificate");
        std::fs::write(&key_path, leaf_key.serialize_pem()).expect("write server key");
        let config = TlsConfig {
            cert: cert_path.to_string_lossy().into_owned(),
            key: key_path.to_string_lossy().into_owned(),
            client_ca: None,
            client_crls: Vec::new(),
            ocsp_responses: Vec::new(),
        };
        Fixture {
            config,
            ca,
            directory,
        }
    }

    fn multi_staple_config(fixture: &Fixture, first: &[u8], second: &[u8]) -> TlsConfig {
        let chain_path = fixture.directory.path().join("chain.pem");
        let leaf_pem = std::fs::read_to_string(&fixture.config.cert).expect("read leaf PEM");
        std::fs::write(&chain_path, format!("{leaf_pem}{}", fixture.ca.pem()))
            .expect("write certificate chain");
        let first_path = fixture.directory.path().join("leaf.ocsp");
        let second_path = fixture.directory.path().join("intermediate.ocsp");
        std::fs::write(&first_path, first).expect("write leaf staple");
        std::fs::write(&second_path, second).expect("write intermediate staple");

        let mut config = fixture.config.clone();
        config.cert = chain_path.to_string_lossy().into_owned();
        config.ocsp_responses = vec![
            Some(first_path.to_string_lossy().into_owned()),
            Some(second_path.to_string_lossy().into_owned()),
        ];
        config
    }

    fn client_config(ca: &Certificate) -> Arc<ClientConfig> {
        let mut provider = rustls::crypto::aws_lc_rs::default_provider();
        provider.cipher_suites =
            vec![rustls::crypto::aws_lc_rs::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256];
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(ca.der().clone())
            .expect("add test CA to rustls root store");
        Arc::new(
            ClientConfig::builder_with_provider(Arc::new(provider))
                .with_protocol_versions(&[&rustls::version::TLS12])
                .expect("pin client to TLS 1.2")
                .with_root_certificates(roots)
                .with_no_client_auth(),
        )
    }

    fn server_name() -> rustls_pki_types::ServerName<'static> {
        ServerName::try_from("localhost")
            .expect("localhost server name")
            .to_owned()
    }

    #[test]
    fn startup_guard_does_not_block_the_daemon() {
        startup_guard().expect("TLS backend must permit startup");
    }

    #[test]
    fn multiple_ocsp_responses_are_loaded_in_chain_order() {
        let fixture = fixture();
        let mut config = multi_staple_config(&fixture, STAPLE_A, STAPLE_B);
        let loaded = load_server_config(&config).expect("load multi-staple configuration");
        assert_eq!(loaded.certificates.len(), 2);
        assert_eq!(
            loaded.ocsp_responses,
            vec![Some(STAPLE_A.to_vec()), Some(STAPLE_B.to_vec())]
        );

        config.ocsp_responses[1] = None;
        let loaded = load_server_config(&config).expect("load leaf-only configuration");
        assert_eq!(loaded.ocsp_responses, vec![Some(STAPLE_A.to_vec()), None]);
    }

    #[test]
    fn unsupported_policy_and_invalid_material_fail_closed() {
        let fixture = fixture();
        let mut config = fixture.config.clone();
        config.ocsp_responses = vec![None, None];
        assert!(
            load_server_config(&config)
                .err()
                .expect("more responses than certificates")
                .to_string()
                .contains("2 entries but certificate chain has 1 certificates")
        );

        config.ocsp_responses.clear();
        config.client_ca = Some("unused.pem".to_owned());
        assert!(
            load_server_config(&config)
                .err()
                .expect("client CA")
                .to_string()
                .contains("client_ca is unsupported")
        );

        config.client_ca = None;
        config.client_crls = vec!["unused.crl".to_owned()];
        assert!(
            load_server_config(&config)
                .err()
                .expect("client CRL")
                .to_string()
                .contains("client_crls is unsupported")
        );

        config.client_crls.clear();
        let empty_path = fixture.directory.path().join("empty.ocsp");
        std::fs::write(&empty_path, []).expect("write empty staple");
        config.ocsp_responses = vec![Some(empty_path.to_string_lossy().into_owned())];
        assert!(
            load_server_config(&config)
                .err()
                .expect("empty staple")
                .to_string()
                .contains("OCSP response must not be empty")
        );
    }

    #[tokio::test]
    async fn protected_stream_carries_application_data_both_ways() {
        let fixture = fixture();
        let config = Arc::new(load_server_config(&fixture.config).expect("load TLS config"));
        let acceptor = QidAcceptor::new(config);
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);

        let server = tokio::spawn(async move {
            let (mut stream, ()) = acceptor.accept(server_io, ()).await.expect("accept TLS");
            let mut request = [0u8; 5];
            stream.read_exact(&mut request).await.expect("read request");
            assert_eq!(&request, b"hello");
            stream.write_all(b"world!").await.expect("write response");
            stream.flush().await.expect("flush response");
        });
        let client = tokio::spawn(async move {
            let connector = TlsConnector::from(client_config(&fixture.ca));
            let mut stream = connector
                .connect(server_name(), client_io)
                .await
                .expect("client handshake");
            assert_eq!(
                stream.get_ref().1.protocol_version(),
                Some(rustls::ProtocolVersion::TLSv1_2)
            );
            stream.write_all(b"hello").await.expect("write request");
            stream.flush().await.expect("flush request");
            let mut response = [0u8; 6];
            stream
                .read_exact(&mut response)
                .await
                .expect("read response");
            assert_eq!(&response, b"world!");
        });
        tokio::try_join!(server, client).expect("both TLS tasks complete");
    }

    #[tokio::test]
    async fn serve_https_answers_http_and_shuts_down_gracefully() {
        let fixture = fixture();
        let config = fixture.config.clone();
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind test listener");
        let address = listener.local_addr().expect("listener address");
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let app = Router::new().route("/ping", get(|| async { "pong" }));
            serve_https(&config, listener, app, async {
                let _ = shutdown_rx.await;
            })
            .await
        });

        let connector = TlsConnector::from(client_config(&fixture.ca));
        let socket = TcpStream::connect(address)
            .await
            .expect("connect to listener");
        let mut tls = tokio::time::timeout(
            Duration::from_secs(5),
            connector.connect(server_name(), socket),
        )
        .await
        .expect("client handshake timeout")
        .expect("client handshake");
        tls.write_all(b"GET /ping HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await
            .expect("write HTTP request");
        let mut response = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), tls.read_to_end(&mut response))
            .await
            .expect("HTTP response timeout")
            .expect("read HTTP response");
        let response = String::from_utf8_lossy(&response);
        assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");
        assert!(response.contains("\r\n\r\npong"), "{response}");

        shutdown_tx.send(()).expect("signal shutdown");
        tokio::time::timeout(Duration::from_secs(10), server)
            .await
            .expect("server shutdown timeout")
            .expect("server task")
            .expect("serve HTTPS");
    }

    #[derive(Debug, PartialEq, Eq)]
    struct BcDone {
        status_type: u8,
        count: usize,
        first: Vec<u8>,
        second: Vec<u8>,
    }

    fn parse_bc_done(line: &str) -> Result<BcDone, String> {
        let mut fields = line.split_whitespace();
        let status_type = fields
            .next()
            .ok_or_else(|| "missing status type in DONE line".to_owned())?
            .parse()
            .map_err(|error| format!("invalid status type: {error}"))?;
        let count = fields
            .next()
            .ok_or_else(|| "missing staple count in DONE line".to_owned())?
            .parse()
            .map_err(|error| format!("invalid staple count: {error}"))?;
        let first = fields
            .next()
            .ok_or_else(|| "missing first staple in DONE line".to_owned())?;
        let second = fields
            .next()
            .ok_or_else(|| "missing second staple in DONE line".to_owned())?;
        if fields.next().is_some() {
            return Err("unexpected extra DONE fields".to_owned());
        }
        Ok(BcDone {
            status_type,
            count,
            first: hex::decode(first).map_err(|error| format!("invalid first staple: {error}"))?,
            second: hex::decode(second)
                .map_err(|error| format!("invalid second staple: {error}"))?,
        })
    }

    /// Bridge the line-oriented Bouncy Castle harness to the real listener
    /// socket: `C` records go to the socket, socket bytes become `S` records.
    async fn bridge_bctls_client(
        socket: &mut TcpStream,
        lines: &mut tokio::sync::mpsc::UnboundedReceiver<String>,
        writes: &tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
    ) -> Result<BcDone, String> {
        let mut buffer = vec![0u8; 16 * 1024];
        loop {
            tokio::select! {
                line = lines.recv() => {
                    let line = line.ok_or_else(|| {
                        "Bouncy Castle client closed stdout before DONE".to_owned()
                    })?;
                    if let Some(client_hex) = line.strip_prefix("C ") {
                        let bytes = hex::decode(client_hex.trim())
                            .map_err(|error| format!("invalid C record: {error}"))?;
                        socket.write_all(&bytes).await
                            .map_err(|error| format!("write client record: {error}"))?;
                        socket.flush().await
                            .map_err(|error| format!("flush client record: {error}"))?;
                    } else if let Some(result) = line.strip_prefix("DONE ") {
                        return parse_bc_done(result.trim());
                    } else if let Some(error) = line.strip_prefix("ERR ") {
                        return Err(format!("Bouncy Castle client failed: {error}"));
                    } else {
                        return Err(format!("unexpected Bouncy Castle client line: {line}"));
                    }
                }
                read = socket.read(&mut buffer) => {
                    let count = read.map_err(|error| format!("read listener record: {error}"))?;
                    if count == 0 {
                        return Err("listener closed the socket before DONE".to_owned());
                    }
                    let line = format!("S {}\n", hex::encode(&buffer[..count]));
                    writes.send(line.into_bytes())
                        .map_err(|_| "Bouncy Castle stdin writer stopped".to_owned())?;
                }
            }
        }
    }

    #[tokio::test]
    #[ignore = "requires the pinned Bouncy Castle jars and Java in CI"]
    async fn bctls_listener_receives_two_distinct_staples() {
        let jars = std::env::var_os("QID_BCTLS_JARS").expect(
            "QID_BCTLS_JARS must be set when running the ignored Bouncy Castle listener test",
        );
        let classes = std::env::var_os("QID_BCTLS_CLASSES")
            .expect("QID_BCTLS_CLASSES must point at compiled V2Client classes");
        let java = std::env::var_os("JAVA").unwrap_or_else(|| "java".into());
        let classpath = format!("{}:{}", jars.to_string_lossy(), classes.to_string_lossy());

        let fixture = fixture();
        let config = multi_staple_config(&fixture, BC_STAPLE_A, BC_STAPLE_B);
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind test listener");
        let address = listener.local_addr().expect("listener address");
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let server_config = config.clone();
        let server = tokio::spawn(async move {
            let app = Router::new().route("/ping", get(|| async { "pong" }));
            serve_https(&server_config, listener, app, async {
                let _ = shutdown_rx.await;
            })
            .await
        });

        let mut socket = TcpStream::connect(address)
            .await
            .expect("connect to the listener");
        let mut child = Command::new(java)
            .arg("-cp")
            .arg(&classpath)
            .arg("V2Client")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn Bouncy Castle client");

        // Stdio is blocking; keep it on dedicated threads so the bridge's
        // timeout is never starved by a stalled peer.
        let stdout = child.stdout.take().expect("child stdout");
        let (lines_tx, mut lines_rx) = tokio::sync::mpsc::unbounded_channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let Ok(line) = line else { break };
                if lines_tx.send(line).is_err() {
                    break;
                }
            }
        });
        let stdin = child.stdin.take().expect("child stdin");
        let (writes_tx, mut writes_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
        std::thread::spawn(move || {
            let mut stdin = stdin;
            while let Some(bytes) = writes_rx.blocking_recv() {
                if stdin.write_all(&bytes).is_err() || stdin.flush().is_err() {
                    break;
                }
            }
        });

        let done = tokio::time::timeout(
            Duration::from_secs(30),
            bridge_bctls_client(&mut socket, &mut lines_rx, &writes_tx),
        )
        .await
        .unwrap_or_else(|_| {
            let _ = child.kill();
            panic!("Bouncy Castle interop bridge timed out");
        })
        .unwrap_or_else(|error| {
            let _ = child.kill();
            panic!("{error}");
        });

        assert_eq!(done.status_type, 2, "RFC 6961 ocsp_multi status type");
        assert_eq!(done.count, 2, "Bouncy Castle must report two staples");
        assert_eq!(done.first.as_slice(), BC_STAPLE_A);
        assert_eq!(done.second.as_slice(), BC_STAPLE_B);
        assert_ne!(BC_STAPLE_A, BC_STAPLE_B);
        assert!(!server.is_finished(), "listener task failed during interop");

        let status = tokio::time::timeout(
            Duration::from_secs(10),
            tokio::task::spawn_blocking(move || child.wait()),
        )
        .await
        .expect("Bouncy Castle client wait timeout")
        .expect("Bouncy Castle client wait task")
        .expect("wait for Bouncy Castle client");
        assert!(
            status.success(),
            "Bouncy Castle client exited with {status}"
        );

        drop(socket);
        shutdown_tx.send(()).expect("signal shutdown");
        tokio::time::timeout(Duration::from_secs(10), server)
            .await
            .expect("server shutdown timeout")
            .expect("server task")
            .expect("serve HTTPS");
    }
}
