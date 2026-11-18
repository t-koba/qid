#![no_main]

use libfuzzer_sys::fuzz_target;
use qid_tls::tls13::certificate::{parse, parse_raw_public_key};

fuzz_target!(|data: &[u8]| {
    let _ = parse(data);
    let _ = parse_raw_public_key(data, data);
});
