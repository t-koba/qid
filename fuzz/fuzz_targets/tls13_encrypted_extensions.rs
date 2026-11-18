#![no_main]

use libfuzzer_sys::fuzz_target;
use qid_tls::tls13::encrypted_extensions::{parse, ParseParams};

fuzz_target!(|data: &[u8]| {
    let offered: Vec<u16> = data
        .chunks_exact(2)
        .map(|pair| u16::from_be_bytes([pair[0], pair[1]]))
        .collect();
    let _ = parse(
        data,
        ParseParams {
            offered_extensions: &offered,
            cert_with_extern_psk: data.first().is_some_and(|byte| byte & 1 == 1),
        },
    );
});
