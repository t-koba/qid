#![no_main]

use libfuzzer_sys::fuzz_target;
use qid_tls::tls13::certificate_request::parse;

fuzz_target!(|data: &[u8]| {
    let _ = parse(data);
});
