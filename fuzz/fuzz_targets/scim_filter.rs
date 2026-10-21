#![no_main]

use libfuzzer_sys::fuzz_target;
use qid_scim::filter::parse_eq_filter;

fuzz_target!(|data: &[u8]| {
    if let Ok(input) = std::str::from_utf8(data) {
        // The fuzzer drives the parser the product runs, so the paths that
        // decode a quoted value are covered instead of a copy of the parser.
        let _ = parse_eq_filter(input, &["displayName", "userName"]);
    }
});
