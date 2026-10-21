#![no_main]

use libfuzzer_sys::fuzz_target;
use qid_scim::filter::{parse_eq_filter, parse_eq_filter_value};

fuzz_target!(|data: &[u8]| {
    if let Ok(input) = std::str::from_utf8(data) {
        // The fuzzer drives the parser the product runs, so the paths that
        // decode a quoted value are covered instead of a copy of the parser.
        let _ = parse_eq_filter(input, &["displayName", "userName"]);
        // The attribute allowlist is checked before the value is decoded, so
        // feeding the whole filter rarely reaches the decoder. The decoder
        // is driven directly as well, which is where the escape decoding
        // happens.
        let _ = parse_eq_filter_value(input);
    }
});
