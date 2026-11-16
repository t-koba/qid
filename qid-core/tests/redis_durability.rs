#![cfg(feature = "redis-cache")]

use qid_core::cache::redis_cache::RedisCache;
use std::{
    io::{BufReader, Write},
    net::{Shutdown, TcpListener},
    num::NonZeroU32,
    thread,
    time::Duration,
};

// A tiny RESP peer checks command ordering and malformed/short acknowledgements
// without Redis, AOF, or external endpoints. The real server/restart proof lives
// in the federation fixture. Never include commands or endpoints in diagnostics.
#[allow(clippy::expect_used)] // Fixture setup failures are test failures.
fn exchange(set_reply: &[u8], wait_reply: Option<&[u8]>) -> qid_core::error::QidResult<bool> {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind fixture");
    let address = listener.local_addr().expect("fixture address");
    let set_reply = set_reply.to_vec();
    let wait_reply = wait_reply.map(<[u8]>::to_vec);
    let server = thread::spawn(move || {
        let (stream, _) = listener.accept().expect("accept fixture connection");
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .expect("fixture deadline");
        let mut stream = BufReader::new(stream);
        let mut parser = redis::Parser::new();
        loop {
            let value = parser
                .parse_value(&mut stream)
                .expect("read fixture command");
            let args: Vec<Vec<u8>> = redis::from_redis_value(&value).expect("command array");
            if args.first().is_some_and(|arg| arg == b"CLIENT") {
                stream.get_mut().write_all(b"+OK\r\n").expect("setup reply");
                continue;
            }
            assert!(
                args == [
                    b"SET".as_slice(),
                    b"opaque-test-key",
                    b"",
                    b"NX",
                    b"EX",
                    b"601",
                ],
                "unexpected SET command"
            );
            stream.get_mut().write_all(&set_reply).expect("SET reply");
            break;
        }
        if let Some(reply) = wait_reply {
            let value = parser.parse_value(&mut stream).expect("read WAITAOF");
            let args: Vec<Vec<u8>> = redis::from_redis_value(&value).expect("command array");
            assert!(
                args == [b"WAITAOF".as_slice(), b"1", b"0", b"2000"],
                "unexpected WAITAOF command"
            );
            stream.get_mut().write_all(&reply).expect("WAITAOF reply");
        }
        stream
            .get_mut()
            .shutdown(Shutdown::Write)
            .expect("finish replies");
        // The client must not send WAITAOF for a duplicate or invalid SET,
        // nor send DEL to roll back a write after a failed acknowledgement.
        assert!(parser.parse_value(&mut stream).is_err());
    });
    let cache = RedisCache::new(&format!("redis://{address}/")).expect("fixture connection");
    let result = cache.set_if_absent_wait_aof(
        "opaque-test-key",
        Vec::new(),
        601,
        NonZeroU32::new(2000).expect("nonzero fixture wait"),
    );
    drop(cache);
    server.join().expect("RESP fixture panicked");
    result
}

#[test]
fn local_aof_requires_exact_ack_and_never_undoes_uncertain_writes() {
    assert!(exchange(b"+OK\r\n", Some(b"*2\r\n:1\r\n:0\r\n")).unwrap());
    // Replica count does not substitute for or invalidate the local ack.
    assert!(exchange(b"+OK\r\n", Some(b"*2\r\n:1\r\n:2\r\n")).unwrap());
    assert!(!exchange(b"$-1\r\n", None).unwrap());
    for reply in [
        b"*2\r\n:0\r\n:9\r\n".as_slice(),     // local wait timed out
        b"*2\r\n:2\r\n:0\r\n",                // invalid local count
        b"*1\r\n:1\r\n",                      // short array
        b"*3\r\n:1\r\n:0\r\n:0\r\n",          // extra field
        b"*2\r\n:1\r\n:-1\r\n",               // invalid replica count
        b"*2\r\n$1\r\n1\r\n:0\r\n",           // wrong type
        b"-ERR sensitive-server-details\r\n", // unsupported/disabled/error
        b"*2\r\n:1\r\n",                      // truncated wire reply
    ] {
        let error = exchange(b"+OK\r\n", Some(reply)).unwrap_err();
        assert_eq!(
            error.to_string(),
            "internal error: redis local AOF acknowledgement unavailable"
        );
    }
    assert!(exchange(b"+unexpected\r\n", None).is_err());
    assert!(exchange(b"-ERR sensitive-server-details\r\n", None).is_err());
}
