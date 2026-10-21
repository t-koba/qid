//! A tiny loopback LDAP peer, not a connector mock. Only tests may supply
//! non-TLS settings to the private session helper; production enforces TLS.
use super::{
    LdapSearchOptions, ensure_ldap_bind_success, ensure_ldap_search_success, fetch_search_entries,
    ldap_search_with_timeout, ldap_simple_bind_with_timeout, with_ldap_session,
};
use qid_core::config::DirectoryAttributeMapping;
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

/// Read one LDAP message and return its id, operation tag and operation.
async fn read_message(socket: &mut TcpStream) -> (u8, u8, Vec<u8>) {
    assert_eq!(socket.read_u8().await.unwrap(), 0x30);
    let first = socket.read_u8().await.unwrap();
    let len = if first & 0x80 == 0 {
        first as usize
    } else {
        // A request that carries a control can need the long length form.
        let count = (first & 0x7f) as usize;
        let mut bytes = vec![0; count];
        socket.read_exact(&mut bytes).await.unwrap();
        bytes
            .iter()
            .fold(0usize, |length, byte| (length << 8) | *byte as usize)
    };
    let mut body = vec![0; len];
    socket.read_exact(&mut body).await.unwrap();
    assert_eq!(&body[..2], &[0x02, 0x01]);
    // The operation's own length may use the long form, which a request
    // that carries a control needs.
    let first = body[4];
    let (header, op_len) = if first & 0x80 == 0 {
        (1usize, first as usize)
    } else {
        let count = (first & 0x7f) as usize;
        let mut bytes = vec![0; count];
        bytes.copy_from_slice(&body[5..5 + count]);
        (
            count + 1,
            bytes
                .iter()
                .fold(0usize, |length, byte| (length << 8) | *byte as usize),
        )
    };
    // A request that carries controls puts them after the operation, so
    // the operation need not fill the message.
    assert!(
        4 + header + op_len <= body.len(),
        "the operation fits in the message"
    );
    (
        body[2],
        body[3],
        body[4 + header..4 + header + op_len].to_vec(),
    )
}

async fn request(socket: &mut TcpStream, expected_op: u8) -> (u8, Vec<u8>) {
    let (id, op, body) = read_message(socket).await;
    assert_eq!(op, expected_op);
    (id, body)
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

/// A search result entry with the attributes the default mapping reads.
fn search_entry(dn: &str, uid: &str) -> Vec<u8> {
    let attrs = ber(
        0x30,
        &[
            ber(
                0x30,
                &[
                    ber(0x04, b"sAMAccountName"),
                    ber(0x31, &ber(0x04, uid.as_bytes())),
                ]
                .concat(),
            ),
            ber(
                0x30,
                &[
                    ber(0x04, b"userAccountControl"),
                    ber(0x31, &ber(0x04, b"512")),
                ]
                .concat(),
            ),
        ]
        .concat(),
    );
    ber(0x64, &[ber(0x04, dn.as_bytes()), attrs].concat())
}

/// A search result done message, with the paging cookie the server sends.
///
/// The cookie travels in the PagedResults response control, and RFC 4511
/// puts the response controls inside the LDAPResult.
fn search_done(cookie: &[u8]) -> Vec<u8> {
    let mut body = vec![0x0a, 1, 0, 4, 0, 4, 0];
    {
        let value = ber(0x30, &[ber(0x02, &[0x00]), ber(0x04, cookie)].concat());
        let control = ber(
            0x30,
            &[ber(0x04, b"1.2.840.113556.1.4.319"), ber(0x04, &value)].concat(),
        );
        body.extend(ber(0xa0, &control));
    }
    ber(0x65, &body)
}

#[tokio::test]
async fn a_paged_search_follows_the_cookie_the_server_sent() {
    // The peer answers the first search with a paging cookie and the second
    // with none. The search must follow the cookie and collect both pages,
    // so a directory that holds more objects than one page returns syncs.
    tokio::time::timeout(DEADLINE, async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ldap://{}", listener.local_addr().unwrap());
        let server = async {
            let (mut socket, _) = listener.accept().await.unwrap();
            let (id, op, _) = read_message(&mut socket).await;
            assert_eq!(op, 0x63, "the first request is a search");
            socket
                .write_all(&message(id, search_entry("uid=alice,dc=test", "alice")))
                .await
                .unwrap();
            socket
                .write_all(&message(id, search_done(&[7])))
                .await
                .unwrap();
            let (id, op, _) = read_message(&mut socket).await;
            if op == 0x42 {
                // The client gave up and unbound.
                return;
            }
            assert_eq!(op, 0x63, "the second request is a search");
            socket
                .write_all(&message(id, search_entry("uid=bob,dc=test", "bob")))
                .await
                .unwrap();
            socket
                .write_all(&message(id, search_done(&[])))
                .await
                .unwrap();
            // The client unbinds and closes the connection.
            let _ = read_message(&mut socket).await;
            assert_closed(&mut socket).await;
        };
        let client = with_ldap_session(ldap3::LdapConnSettings::new(), &url, 5, async |ldap| {
            let options = LdapSearchOptions {
                page_size: Some(1),
                max_entries: None,
                tls_insecure: false,
                timeout_secs: 5,
            };
            let entries = fetch_search_entries(
                ldap,
                "dc=test",
                "(uid=alice)",
                &DirectoryAttributeMapping::default(),
                &options,
                Duration::from_secs(5),
            )
            .await?;
            assert_eq!(entries.len(), 2, "both pages are collected");
            assert_eq!(entries[0].uid, "alice");
            assert_eq!(entries[1].uid, "bob");
            Ok(())
        });
        let ((), result) = tokio::join!(server, client);
        result.unwrap();
    })
    .await
    .expect("the paged search stalled (peer not running or not closed)");
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
            let timeout = Duration::from_secs(1);
            let error = if fail_search {
                ldap_simple_bind_with_timeout(ldap, "cn=test", "test", timeout)
                    .await
                    .unwrap();
                // This uses the same timeout helper as production; no test-only reset.
                ldap_search_with_timeout(
                    ldap,
                    "dc=test",
                    ldap3::Scope::Subtree,
                    "(uid=alice)",
                    vec!["uid"],
                    timeout,
                )
                .await
                .unwrap_err()
            } else {
                ldap_simple_bind_with_timeout(ldap, "cn=test", "test", timeout)
                    .await
                    .unwrap_err()
            };
            assert!(error.to_string().to_ascii_lowercase().contains("timeout"));
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
