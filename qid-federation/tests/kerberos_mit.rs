//! Test-only live MIT proof. Run through scripts/kerberos/test-mit-spnego.py,
//! which owns the realm, credentials, process-group deadline and cleanup.
//! Ordinary workspace tests report this proof as ignored, never as passed.
use krb5::{
    KerberosError, Keytab,
    acceptor::{AcceptOptions, DEFAULT_CLOCK_SKEW_SECS},
    rcache::ReplayStore,
    spnego::SpnegoAcceptor,
};
use qid_core::cache::MemoryCache;
use qid_federation::KerberosReplayStore;
use std::{
    io::{self, Read, Write},
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
    sync::Arc,
};

const SERVICE: &str = "HTTP/acceptor.qid.test@QID.MIT.TEST";
const WRONG_SERVICE: &str = "HTTP/other.qid.test@QID.MIT.TEST";
const CLIENT: &str = "client@QID.MIT.TEST";
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

#[derive(Debug)]
struct TestReplayStore(KerberosReplayStore);

impl ReplayStore for TestReplayStore {
    fn insert(&self, tag: &[u8], now: i64, expires: i64) -> io::Result<bool> {
        self.0.insert(tag, now, expires)
    }
}

fn acceptor<'k>(keytab: &'k Keytab, cache: &Arc<MemoryCache>) -> SpnegoAcceptor<'k> {
    // krb5 1.0.0 makes AcceptOptions non_exhaustive and offers only Default
    // for construction outside its crate. Overwrite EVERY public field before
    // handing options to an acceptor; never use its environment-selected store.
    let mut options = AcceptOptions::default();
    options.max_skew_secs = DEFAULT_CLOCK_SKEW_SECS;
    options.channel_bindings = None;
    options.replay_cache = Some(Arc::new(TestReplayStore(KerberosReplayStore::new(
        cache.clone(),
    ))));
    // Distinct adapter instances model independent acceptors sharing one cache.
    SpnegoAcceptor::with_options(keytab, options)
}

#[test]
#[ignore = "requires disposable MIT realm; run scripts/kerberos/test-mit-spnego.py"]
fn mit_spnego_acceptor_proof() -> io::Result<()> {
    let keytab_path = std::env::var_os("QID_MIT_KEYTAB").expect("run the MIT fixture script");
    let keytab =
        Keytab::load(keytab_path).unwrap_or_else(|_| panic!("load fixture service keytab"));
    let cache = Arc::new(MemoryCache::new());
    let mut mit = MitPeer::new(SERVICE)?;
    let original = mit.initial()?;
    let mut server = acceptor(&keytab, &cache);
    let mut incoming = original.clone();
    let mut mutual_complete = false;
    for _ in 0..4 {
        let reply = server
            .step(&incoming)
            .unwrap_or_else(|_| panic!("MIT SPNEGO token was not accepted"));
        let reply = reply.expect("acceptor must answer MIT with mutual authentication");
        assert!(!reply.is_empty(), "acceptor response must not be empty");
        mit.send(&reply)?;
        let (complete, next) = mit.receive()?;
        if complete && next.is_empty() {
            mutual_complete = true;
            break;
        }
        assert!(!next.is_empty(), "MIT negotiation stalled");
        incoming = next;
    }
    // The independent MIT initiator verifies the AP-REP before reporting
    // complete, and its helper separately requires the mutual-auth flag.
    assert!(
        mutual_complete,
        "MIT did not verify the mutual handshake/AP-REP"
    );
    assert!(server.is_spnego(), "must exercise SPNEGO, not raw Kerberos");
    assert!(
        server.is_established(),
        "acceptor did not establish a context"
    );
    let context = server.context().expect("accepted Kerberos context");
    assert!(
        context.client_principal == CLIENT,
        "unexpected client identity"
    );
    assert!(
        context.service_principal == SERVICE,
        "unexpected service identity"
    );
    assert!(mit.child.wait().expect("reap MIT initiator").success());

    let mut replay = acceptor(&keytab, &cache);
    assert!(
        matches!(replay.step(&original), Err(KerberosError::Replay(_))),
        "exact initial token must be refused specifically as replay"
    );
    assert!(!replay.is_established() && replay.context().is_none());

    // Mutate a token already proven valid above, not an unrelated fixture.
    let mut damaged = original.clone();
    // MIT's optimistic token ends with the encrypted authenticator. Flip its
    // final checksum byte, leaving DER lengths untouched. Require a crypto
    // failure below: a parser error or replay is NOT a passing tamper test.
    *damaged.last_mut().expect("nonempty MIT token") ^= 1;
    let mut tamper = acceptor(&keytab, &cache);
    assert!(
        matches!(
            tamper.step(&damaged),
            Err(KerberosError::InvalidAuthenticator(_))
        ),
        "tampered MIT token must fail cryptographic verification"
    );
    assert!(!tamper.is_established() && tamper.context().is_none());

    // The other principal exists in the MIT realm, so this is a genuine
    // KDC-issued ticket, not an unknown-service failure at the initiator.
    // Only the intended service's key is exported to the acceptor keytab.
    let mut other = MitPeer::new(WRONG_SERVICE)?;
    let wrong_token = other.initial()?;
    let mut wrong = acceptor(&keytab, &cache);
    assert!(
        matches!(
            wrong.step(&wrong_token),
            Err(KerberosError::PrincipalNotFound(_))
        ),
        "real ticket for another service must not be accepted"
    );
    assert!(!wrong.is_established() && wrong.context().is_none());
    Ok(())
}
