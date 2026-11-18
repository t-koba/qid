#![no_main]

use libfuzzer_sys::fuzz_target;
use qid_tls::tls13::certificate_verify::{parse, signed_content, CertificateVerifySender};

fuzz_target!(|data: &[u8]| {
    let _ = parse(data);
    if let Ok(parsed) = parse(data) {
        let hash: [u8; 32] = data
            .get(..32)
            .and_then(|slice| slice.try_into().ok())
            .unwrap_or([0; 32]);
        let _ = signed_content(CertificateVerifySender::Client, &hash);
        let _ = parsed.algorithm;
    }
});
