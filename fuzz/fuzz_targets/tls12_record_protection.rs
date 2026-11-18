#![no_main]

use libfuzzer_sys::fuzz_target;
use qid_tls::tls12::{KeyBlock, RecordProtector};

fuzz_target!(|data: &[u8]| {
    // Fixed, public test keys: only the record parser is under test.
    let block = KeyBlock {
        client_write_key: [0x11; 16],
        server_write_key: [0x22; 16],
        client_write_iv: [0x33; 4],
        server_write_iv: [0x44; 4],
    };
    let mut protector = RecordProtector::new(&block);
    let _ = protector.open(data);
});
