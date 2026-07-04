use proptest::prelude::*;

proptest! {
    #[test]
    fn hotp_code_always_has_correct_digit_count(
        secret in prop::collection::vec(any::<u8>(), 1..64),
        counter in any::<u64>(),
        digits in 6u32..=8u32,
    ) {
        let code = qid_crypto::hotp::hotp_generate(&secret, counter, digits).unwrap();
        let expected_len = digits as usize;
        prop_assert_eq!(
            code.len(),
            expected_len,
            "HOTP code length mismatch: digits={}", digits
        );
        prop_assert!(
            code.chars().all(|c| c.is_ascii_digit()),
            "HOTP code must be all digits"
        );
    }

    #[test]
    fn hotp_verify_rejects_wrong_code(
        secret in prop::collection::vec(any::<u8>(), 1..64),
        counter in any::<u64>(),
        digits in 6u32..=8u32,
    ) {
        let code = qid_crypto::hotp::hotp_generate(&secret, counter, digits).unwrap();
        if let Some(d) = code.chars().next() {
            let wrong = format!("{}{}", (d as u8 ^ 1) as char, &code[1..]);
            prop_assert!(
                !qid_crypto::hotp::hotp_verify(&secret, counter, &wrong, digits).unwrap(),
                "HOTP must reject wrong code"
            );
        }
    }
}
