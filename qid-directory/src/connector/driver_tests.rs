//! A tiny loopback LDAP peer, not a connector mock. Only tests may supply
//! non-TLS settings to the private session helper; production enforces TLS.
use super::{ensure_ldap_bind_success, ensure_ldap_search_success, with_ldap_session};
use qid_core::error::QidError;
use std::time::Duration;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

const DEADLINE: Duration = Duration::from_secs(5);

// The fixture uses short BER lengths and single-byte message IDs throughout.
fn ber(tag: u8, body: &[u8]) -> Vec<u8> {
    assert!(body.len() < 128);
    [vec![tag, body.len() as u8], body.to_vec()].concat()
}

fn message(id: u8, op: Vec<u8>) -> Vec<u8> {
    ber(0x30, &[vec![0x02, 0x01, id], op].concat())
}

async fn request(socket: &mut TcpStream, expected_op: u8) -> (u8, Vec<u8>) {
    assert_eq!(socket.read_u8().await.unwrap(), 0x30);
    let len = socket.read_u8().await.unwrap();
    assert!(len < 128);
    let mut body = vec![0; len as usize];
    socket.read_exact(&mut body).await.unwrap();
    assert_eq!(&body[..2], &[0x02, 0x01]);
    assert_eq!(body[3], expected_op);
    assert_eq!(body[4] as usize, body.len() - 5);
    (body[2], body[5..].to_vec())
}

async fn bind(socket: &mut TcpStream) {
    bind_with_code(socket, 0).await;
}

async fn bind_with_code(socket: &mut TcpStream, result_code: u8) {
    let (id, body) = request(socket, 0x60).await;
    assert_eq!(
        body,
        [
            vec![0x02, 0x01, 0x03],
            ber(0x04, b"cn=test"),
            ber(0x80, b"test")
        ]
        .concat()
    );
    // BindResponse with the requested result code and empty diagnostics.
    socket
        .write_all(&message(id, ber(0x61, &[0x0a, 1, result_code, 4, 0, 4, 0])))
        .await
        .unwrap();
}

async fn assert_closed(socket: &mut TcpStream) {
    assert_eq!(socket.read(&mut [0]).await.unwrap(), 0);
}

#[tokio::test]
async fn ldap_driver_bind_search_round_trip() {
    tokio::time::timeout(DEADLINE, async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ldap://{}", listener.local_addr().unwrap());
        let server = async {
            let (mut socket, _) = listener.accept().await.unwrap();
            bind(&mut socket).await;
            let (id, body) = request(&mut socket, 0x63).await;
            assert_eq!(
                body,
                [
                    ber(0x04, b"dc=test"),
                    vec![0x0a, 1, 2, 0x0a, 1, 0, 2, 1, 0, 2, 1, 0, 1, 1, 0],
                    ber(0xa3, &[ber(0x04, b"uid"), ber(0x04, b"alice")].concat()),
                    ber(0x30, &ber(0x04, b"uid")),
                ]
                .concat()
            );
            // SearchResultEntry with a real uid attribute, followed by SearchResultDone.
            let attr = ber(
                0x30,
                &[ber(0x04, b"uid"), ber(0x31, &ber(0x04, b"alice"))].concat(),
            );
            let entry = ber(
                0x64,
                &[ber(0x04, b"uid=alice,dc=test"), ber(0x30, &attr)].concat(),
            );
            socket.write_all(&message(id, entry)).await.unwrap();
            socket
                .write_all(&message(id, ber(0x65, &[0x0a, 1, 0, 4, 0, 4, 0])))
                .await
                .unwrap();
            request(&mut socket, 0x42).await;
            assert_closed(&mut socket).await;
        };
        let client = with_ldap_session(ldap3::LdapConnSettings::new(), &url, 1, async |ldap| {
            ldap.simple_bind("cn=test", "test").await.unwrap();
            let ldap3::SearchResult(entries, _) = ldap
                .search("dc=test", ldap3::Scope::Subtree, "(uid=alice)", vec!["uid"])
                .await
                .unwrap();
            assert_eq!(entries.len(), 1);
            let entry = ldap3::SearchEntry::construct(entries.into_iter().next().unwrap());
            assert_eq!(entry.dn, "uid=alice,dc=test");
            assert_eq!(entry.attrs["uid"], ["alice"]);
            Ok(())
        });
        let ((), result) = tokio::join!(server, client);
        result.unwrap();
    })
    .await
    .expect("LDAP round trip stalled (driver not running or not closed)");
}

#[tokio::test]
async fn ldap_bind_protocol_failure_is_rejected_before_search() {
    tokio::time::timeout(DEADLINE, async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ldap://{}", listener.local_addr().unwrap());
        let server = async {
            let (mut socket, _) = listener.accept().await.unwrap();
            bind_with_code(&mut socket, 49).await;
            request(&mut socket, 0x42).await;
            assert_closed(&mut socket).await;
        };
        let client = with_ldap_session(ldap3::LdapConnSettings::new(), &url, 1, async |ldap| {
            let result =
                ldap.simple_bind("cn=test", "test")
                    .await
                    .map_err(|e| QidError::Internal {
                        message: format!("LDAP bind transport failed: {e}"),
                    })?;
            ensure_ldap_bind_success(result)?;
            Ok(())
        });
        let ((), result) = tokio::join!(server, client);
        assert!(result.unwrap_err().to_string().contains("rc=49"));
    })
    .await
    .expect("bind protocol failure cleanup stalled");
}

#[tokio::test]
async fn ldap_partial_search_result_is_rejected_and_discarded() {
    tokio::time::timeout(DEADLINE, async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ldap://{}", listener.local_addr().unwrap());
        let server = async {
            let (mut socket, _) = listener.accept().await.unwrap();
            bind(&mut socket).await;
            let (id, _) = request(&mut socket, 0x63).await;
            let attr = ber(
                0x30,
                &[ber(0x04, b"uid"), ber(0x31, &ber(0x04, b"alice"))].concat(),
            );
            let entry = ber(
                0x64,
                &[ber(0x04, b"uid=alice,dc=test"), ber(0x30, &attr)].concat(),
            );
            socket.write_all(&message(id, entry)).await.unwrap();
            // sizeLimitExceeded after a partial entry must make the whole search fail.
            socket
                .write_all(&message(id, ber(0x65, &[0x0a, 1, 4, 4, 0, 4, 0])))
                .await
                .unwrap();
            request(&mut socket, 0x42).await;
            assert_closed(&mut socket).await;
        };
        let client = with_ldap_session(ldap3::LdapConnSettings::new(), &url, 1, async |ldap| {
            let bind_result =
                ldap.simple_bind("cn=test", "test")
                    .await
                    .map_err(|e| QidError::Internal {
                        message: format!("LDAP bind transport failed: {e}"),
                    })?;
            ensure_ldap_bind_success(bind_result)?;
            let search_result = ldap
                .search("dc=test", ldap3::Scope::Subtree, "(uid=alice)", vec!["uid"])
                .await
                .map_err(|e| QidError::Internal {
                    message: format!("LDAP search transport failed: {e}"),
                })?;
            let _entries = ensure_ldap_search_success(search_result)?;
            Ok(())
        });
        let ((), result) = tokio::join!(server, client);
        assert!(result.unwrap_err().to_string().contains("rc=4"));
    })
    .await
    .expect("partial search failure cleanup stalled");
}

#[tokio::test]
async fn ldap_driver_unbinds_after_bind_failure() {
    failed_operation(false).await;
}

#[tokio::test]
async fn ldap_driver_unbinds_after_search_failure() {
    failed_operation(true).await;
}

async fn failed_operation(fail_search: bool) {
    tokio::time::timeout(DEADLINE, async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ldap://{}", listener.local_addr().unwrap());
        let server = async {
            let (mut socket, _) = listener.accept().await.unwrap();
            // Leave the selected operation unanswered, forcing an actual LDAP
            // operation timeout rather than injecting an application error.
            if fail_search {
                bind(&mut socket).await;
                request(&mut socket, 0x63).await;
            } else {
                request(&mut socket, 0x60).await;
            }
            request(&mut socket, 0x42).await;
            assert_closed(&mut socket).await;
        };
        let client = with_ldap_session(ldap3::LdapConnSettings::new(), &url, 1, async |ldap| {
            let error = if fail_search {
                ldap.simple_bind("cn=test", "test").await.unwrap();
                // ldap3's timeout is per operation; set this only in the test
                // to force a search failure without changing production policy.
                ldap.with_timeout(Duration::from_secs(1));
                ldap.search("dc=test", ldap3::Scope::Subtree, "(uid=alice)", vec!["uid"])
                    .await
                    .unwrap_err()
            } else {
                ldap.simple_bind("cn=test", "test").await.unwrap_err()
            };
            Err::<(), _>(QidError::Internal {
                message: format!("expected operation failure: {error}"),
            })
        });
        let ((), result) = tokio::join!(server, client);
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("expected operation failure")
        );
    })
    .await
    .expect("failed operation did not unbind and close");
}

#[tokio::test]
async fn ldap_driver_closes_on_session_cancellation() {
    tokio::time::timeout(DEADLINE, async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ldap://{}", listener.local_addr().unwrap());
        // Dropping this future cancels the session, including its owned driver.
        let mut session = Box::pin(with_ldap_session(
            ldap3::LdapConnSettings::new(),
            &url,
            1,
            async |ldap| {
                ldap.simple_bind("cn=test", "test").await.unwrap();
                Ok(())
            },
        ));
        let (mut socket, _) = tokio::select! {
            result = &mut session => panic!("session ended before accepting: {result:?}"),
            accepted = listener.accept() => accepted.unwrap(),
        };
        tokio::select! {
            result = &mut session => panic!("session ended before bind: {result:?}"),
            _ = request(&mut socket, 0x60) => {},
        }
        drop(session);
        assert_closed(&mut socket).await;
    })
    .await
    .unwrap();
}
