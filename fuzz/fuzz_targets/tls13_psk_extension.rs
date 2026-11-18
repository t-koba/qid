#![no_main]

use libfuzzer_sys::fuzz_target;
use qid_tls::tls13::psk_extension::{
    parse_extension, parse_selected_identity, validate_client_hello_companion_extensions,
};

fuzz_target!(|data: &[u8]| {
    let _ = parse_extension(data);
    if data.len() == 2 {
        let _ = parse_selected_identity(data);
    }
    if data.len() >= 2 && data.len() % 2 == 0 {
        let types: Vec<u16> = data
            .chunks_exact(2)
            .map(|pair| u16::from_be_bytes([pair[0], pair[1]]))
            .collect();
        let _ = validate_client_hello_companion_extensions(&types);
    }
});
