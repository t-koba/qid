#![no_main]

use libfuzzer_sys::fuzz_target;
use qid_tls::tls12::{parse_client_hello, select_status_request, HandshakeReassembler};

fuzz_target!(|data: &[u8]| {
    let mut reassembler = HandshakeReassembler::new();
    if let Ok(messages) = reassembler.push_records(data) {
        for message in messages {
            if let Ok(hello) = parse_client_hello(&message.body) {
                let _ = select_status_request(&hello.extensions);
            }
        }
        let _ = reassembler.finish();
    }
});
