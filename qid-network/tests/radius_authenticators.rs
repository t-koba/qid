#![cfg(test)]

use hmac::{Hmac, Mac};
use qid_network::{
    RadiusCode, RadiusPacket, parse_radius_packet, radius_message_authenticator,
    radius_response_authenticator, server, verify_radius_request_authenticator,
};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

#[test]
fn radius_authenticators_preserve_arbitrary_key_and_mismatch_semantics() {
    let request_authenticator = [0x42; 16];
    let body = b"RADIUS attributes";
    for secret in [&b""[..], &b"shared secret"[..], &[0x5a; 100][..]] {
        let mut mac = HmacSha256::new_from_slice(secret).unwrap();
        mac.update(&request_authenticator);
        mac.update(body);
        let expected = mac.finalize().into_bytes();
        assert_eq!(
            radius_response_authenticator(secret, &request_authenticator, body).unwrap(),
            expected[..16]
        );

        let request_mac = radius_message_authenticator(secret, body).unwrap();
        let mut packet = RadiusPacket {
            code: RadiusCode::AccessRequest,
            identifier: 1,
            authenticator: request_mac[..16].try_into().unwrap(),
            attributes: Vec::new(),
        };
        assert!(verify_radius_request_authenticator(secret, &packet, body).unwrap());
        packet.authenticator[0] ^= 1;
        assert!(!verify_radius_request_authenticator(secret, &packet, body).unwrap());

        let response = server::encode_radius_response(
            1,
            &request_authenticator,
            RadiusCode::AccessAccept,
            Vec::new(),
            secret,
        )
        .unwrap();
        let authenticator = parse_radius_packet(&response).unwrap().authenticator;
        let mut unsigned_response = response;
        unsigned_response[4..20].fill(0);
        assert_eq!(
            authenticator,
            radius_response_authenticator(secret, &request_authenticator, &unsigned_response[4..])
                .unwrap()
        );
    }
}
