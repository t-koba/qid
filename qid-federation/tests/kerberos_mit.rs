//! Test-only live MIT proof. Run through scripts/kerberos/test-mit-spnego.py,
//! which owns the realm, credentials, process-group deadline and cleanup.
//! Ordinary workspace tests report this proof as ignored, never as passed.
//!
//! Every ticket here goes through qid_federation's production acceptor: the
//! same loader, options and single-step validation sequence the HTTP route
//! uses. This fixture proves that path against a real MIT KDC; it never builds
//! krb5 keytabs or accept options itself.

use qid_core::cache::MemoryCache;
use qid_federation::kerberos_acceptor::{
    AcceptedNegotiate, KerberosAcceptError, KerberosKeytab, accept_with_options,
    build_accept_options,
};
use std::{
    io::{self, Read, Write},
    path::Path,
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
    sync::Arc,
    time::Duration,
};

const SERVICE: &str = "HTTP/acceptor.qid.test@QID.MIT.TEST";
const WRONG_SERVICE: &str = "HTTP/other.qid.test@QID.MIT.TEST";
const EXPIRED_SERVICE: &str = "HTTP/expired.qid.test@QID.MIT.TEST";
const CLIENT: &str = "client@QID.MIT.TEST";
const REALM: &str = "QID.MIT.TEST";
const MAX_TOKEN: usize = 1024 * 1024; // Fixture IPC budget, not a protocol limit.

struct MitPeer {
    child: Child,
    input: ChildStdin,
    output: ChildStdout,
}

impl MitPeer {
    fn new(target: &str) -> io::Result<Self> {
        let python = std::env::var_os("QID_MIT_PYTHON")
            .ok_or_else(|| io::Error::other("run the MIT fixture script"))?;
        let mut child = Command::new(python)
            .arg(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../scripts/kerberos/mit-initiator.py"
            ))
            .arg(target)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;
        match (child.stdin.take(), child.stdout.take()) {
            (Some(input), Some(output)) => Ok(Self {
                child,
                input,
                output,
            }),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                Err(io::Error::other("MIT pipes unavailable"))
            }
        }
    }

    fn receive(&mut self) -> io::Result<(bool, Vec<u8>)> {
        let mut header = [0; 5];
        self.output.read_exact(&mut header)?;
        assert!(header[0] <= 1, "invalid MIT completion status");
        let size = u32::from_be_bytes([header[1], header[2], header[3], header[4]]) as usize;
        assert!(size <= MAX_TOKEN, "MIT frame exceeds fixture budget");
        let mut token = vec![0; size];
        self.output.read_exact(&mut token)?;
        Ok((header[0] == 1, token))
    }

    fn send(&mut self, token: &[u8]) -> io::Result<()> {
        assert!(!token.is_empty() && token.len() <= MAX_TOKEN);
        self.input.write_all(&(token.len() as u32).to_be_bytes())?;
        self.input.write_all(token)?;
        self.input.flush()
    }

    fn initial(&mut self) -> io::Result<Vec<u8>> {
        let (complete, token) = self.receive()?;
        assert!(!complete, "MIT must wait for mutual authentication/AP-REP");
        assert!(!token.is_empty(), "MIT must produce an initial token");
        Ok(token)
    }
}

impl Drop for MitPeer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// The production contract is category-level: ticket crypto, time, replay and
/// service checks all surface as `NegotiationFailed` with no identity. A check
/// that was dropped and let the ticket through would show as `Ok`, so an `Err`
/// here still proves the acceptor refused the token; only the underlying krb5
/// error distinction is intentionally no longer observable.
fn assert_refused(label: &str, result: Result<AcceptedNegotiate, KerberosAcceptError>) {
    assert_eq!(
        result.err(),
        Some(KerberosAcceptError::NegotiationFailed),
        "{label}"
    );
}

#[test]
#[ignore = "requires disposable MIT realm; run scripts/kerberos/test-mit-spnego.py"]
fn mit_spnego_acceptor_proof() -> io::Result<()> {
    let keytab_path = std::env::var_os("QID_MIT_KEYTAB").expect("run the MIT fixture script");
    let keytab = KerberosKeytab::load(Path::new(&keytab_path))
        .unwrap_or_else(|_| panic!("load fixture service keytab"));
    let cache = Arc::new(MemoryCache::new());
    let mut mit = MitPeer::new(SERVICE)?;
    let original = mit.initial()?;

    // Happy path: production loader, production options, one production step.
    let accepted = accept_with_options(
        &keytab,
        SERVICE,
        REALM,
        build_accept_options(cache.clone()),
        &original,
    )
    .unwrap_or_else(|_| panic!("MIT SPNEGO token was not accepted by production code"));
    let reply = accepted
        .reply
        .expect("acceptor must answer MIT with mutual authentication");
    assert!(!reply.is_empty(), "acceptor response must not be empty");
    mit.send(&reply)?;
    let (complete, next) = mit.receive()?;
    // The independent MIT initiator verifies the AP-REP and requires the
    // mutual-auth GSS flag before it reports completion with no further token.
    assert!(
        complete && next.is_empty(),
        "MIT did not verify the mutual handshake/AP-REP"
    );
    assert_eq!(accepted.identity.client_principal, CLIENT);
    assert_eq!(accepted.identity.client_realm, REALM);
    assert_eq!(accepted.identity.service_principal, SERVICE);
    assert!(mit.child.wait().expect("reap MIT initiator").success());

    // A fresh acceptor with the same shared cache must reject the exact token
    // that the first acceptor just accepted.
    assert_refused(
        "exact initial token must be refused as a replay",
        accept_with_options(
            &keytab,
            SERVICE,
            REALM,
            build_accept_options(cache.clone()),
            &original,
        ),
    );

    // Mutate a token already proven valid above, not an unrelated fixture.
    // MIT's optimistic token ends with the encrypted authenticator. Flip its
    // final checksum byte, leaving DER lengths untouched.
    let mut damaged = original.clone();
    *damaged.last_mut().expect("nonempty MIT token") ^= 1;
    assert_refused(
        "tampered MIT token must fail cryptographic verification",
        accept_with_options(
            &keytab,
            SERVICE,
            REALM,
            build_accept_options(cache.clone()),
            &damaged,
        ),
    );

    // The other principal exists in the MIT realm, so this is a genuine
    // KDC-issued ticket, not an unknown-service failure at the initiator.
    // Only the intended service's key is exported to the acceptor keytab.
    let mut other = MitPeer::new(WRONG_SERVICE)?;
    let wrong_token = other.initial()?;
    assert_refused(
        "real ticket for another service must not be accepted",
        accept_with_options(
            &keytab,
            SERVICE,
            REALM,
            build_accept_options(cache.clone()),
            &wrong_token,
        ),
    );

    // MIT issues this separate service a ten-second ticket. With zero test
    // skew, a real KDC-issued token delayed past endtime must fail at
    // ticket-time validation. Only this request overrides the production
    // default skew; every other case keeps it.
    let expired_keytab_path =
        std::env::var_os("QID_MIT_EXPIRED_KEYTAB").expect("run the MIT fixture script");
    let expired_keytab = KerberosKeytab::load(Path::new(&expired_keytab_path))
        .unwrap_or_else(|_| panic!("load fixture expired-service keytab"));
    let mut expired_peer = MitPeer::new(EXPIRED_SERVICE)?;
    let expired_token = expired_peer.initial()?;
    std::thread::sleep(Duration::from_secs(12));
    let mut options = build_accept_options(cache.clone());
    options.max_skew_secs = 0;
    assert_refused(
        "expired MIT ticket must fail at ticket-time validation",
        accept_with_options(
            &expired_keytab,
            EXPIRED_SERVICE,
            REALM,
            options,
            &expired_token,
        ),
    );
    Ok(())
}
