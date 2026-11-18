//! Hand-written, RFC-derived byte vectors (not captured handshakes).

use super::*;

// RFC 5246 §7.4.1.2: client_version 0x0303, 32-byte random, empty session_id,
// two cipher suites (0x1301, 0x1302), and the null compression method.
const CH_PREFIX: &[u8] = &[
    0x03, 0x03, 0xA1, 0xA1, 0xA1, 0xA1, 0xA1, 0xA1, 0xA1, 0xA1, 0xA1, 0xA1, 0xA1, 0xA1, 0xA1, 0xA1,
    0xA1, 0xA1, 0xA1, 0xA1, 0xA1, 0xA1, 0xA1, 0xA1, 0xA1, 0xA1, 0xA1, 0xA1, 0xA1, 0xA1, 0xA1, 0xA1,
    0xA1, 0xA1, 0x00, 0x00, 0x04, 0x13, 0x01, 0x13, 0x02, 0x01, 0x00,
];

// RFC 6961 §2.2, ocsp_multi with empty ResponderID list and empty Extensions:
// list_len=7; status_type=2; request_len=4; ids_len=0; extensions_len=0.
const V2_MULTI_DATA: &[u8] = &[0x00, 0x07, 0x02, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00];
const V2_MULTI_BLOCK: &[u8] = &[
    0x00, 0x11, 0x00, 0x09, 0x00, 0x07, 0x02, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00,
];

// Same presentation language with status_type=ocsp(1).
const V2_OCSP_DATA: &[u8] = &[0x00, 0x07, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00];
const V2_OCSP_BLOCK: &[u8] = &[
    0x00, 0x11, 0x00, 0x09, 0x00, 0x07, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00,
];

// One ResponderID (length 1) makes the ocsp_multi item unusable here.
const V2_RESPONDER_DATA: &[u8] = &[
    0x00, 0x0A, 0x02, 0x00, 0x07, 0x00, 0x03, 0x00, 0x01, 0x03, 0x00, 0x00,
];
const V2_RESPONDER_BLOCK: &[u8] = &[
    0x00, 0x11, 0x00, 0x0C, 0x00, 0x0A, 0x02, 0x00, 0x07, 0x00, 0x03, 0x00, 0x01, 0x03, 0x00, 0x00,
];

fn hello(extension_block: &[u8]) -> Vec<u8> {
    let mut body = CH_PREFIX.to_vec();
    let len = u16::try_from(extension_block.len()).expect("test extension block fits u16");
    body.extend_from_slice(&len.to_be_bytes());
    body.extend_from_slice(extension_block);
    body
}

fn record(bytes: &[u8]) -> Vec<u8> {
    let mut encoded = vec![0x16, 0x03, 0x03];
    let len = u16::try_from(bytes.len()).expect("test fragment fits u16");
    encoded.extend_from_slice(&len.to_be_bytes());
    encoded.extend_from_slice(bytes);
    encoded
}

#[test]
fn rfc_derived_ocsp_multi_request_with_empty_vectors_is_usable() {
    let body = hello(V2_MULTI_BLOCK);
    let parsed = parse_client_hello(&body).expect("parse RFC-derived ClientHello");
    assert_eq!(parsed.legacy_version, [0x03, 0x03]);
    assert_eq!(parsed.random, &[0xA1; 32][..]);
    assert_eq!(parsed.session_id, &[][..]);
    assert_eq!(parsed.cipher_suites, vec![0x1301, 0x1302]);
    assert_eq!(parsed.compression_methods, &[0x00][..]);
    assert_eq!(parsed.extensions.len(), 1);
    assert_eq!(parsed.extensions[0].ext_type, STATUS_REQUEST_V2);
    assert_eq!(parsed.extensions[0].data, V2_MULTI_DATA);

    let request = parse_status_request_v2(V2_MULTI_DATA).expect("parse status_request_v2");
    assert_eq!(
        request.items,
        vec![StatusRequestItem {
            status_type: OCSP_MULTI,
            responder_ids: &[],
            request_extensions: &[],
        }]
    );
    let selection = select_status_request(&parsed.extensions).expect("select status request");
    assert_eq!(
        selection,
        StatusSelection {
            legacy_status_request_offered: false,
            ocsp_multi_usable: true,
        }
    );
    assert_eq!(
        selection.server_hello_extension(),
        Some([0x00, 0x11, 0x00, 0x00])
    );
}

#[test]
fn rfc_derived_ocsp_only_request_is_not_acknowledged() {
    let body = hello(V2_OCSP_BLOCK);
    let parsed = parse_client_hello(&body).expect("parse RFC-derived ClientHello");
    let request = parse_status_request_v2(V2_OCSP_DATA).expect("parse status_request_v2");
    assert_eq!(request.items[0].status_type, OCSP);
    let selection = select_status_request(&parsed.extensions).expect("select status request");
    assert!(!selection.ocsp_multi_usable);
    assert_eq!(selection.server_hello_extension(), None);
}

#[test]
fn rfc_derived_responder_or_extension_selection_is_not_usable() {
    let body = hello(V2_RESPONDER_BLOCK);
    let parsed = parse_client_hello(&body).expect("parse RFC-derived ClientHello");
    let request = parse_status_request_v2(V2_RESPONDER_DATA).expect("parse status_request_v2");
    assert_eq!(request.items[0].responder_ids, &[0x00, 0x01, 0x03][..]);
    let selection = select_status_request(&parsed.extensions).expect("select status request");
    assert!(!selection.ocsp_multi_usable);
    assert_eq!(selection.server_hello_extension(), None);
}

#[test]
fn rfc_derived_duplicate_extensions_are_rejected() {
    let mut block = V2_MULTI_BLOCK.to_vec();
    block.extend_from_slice(V2_MULTI_BLOCK);
    assert_eq!(
        parse_client_hello(&hello(&block)).err(),
        Some(Tls12Error::DuplicateExtension)
    );

    // A second legacy status_request is a duplicate even without v2 present.
    let extensions = [
        Extension {
            ext_type: STATUS_REQUEST,
            data: V2_OCSP_DATA,
        },
        Extension {
            ext_type: STATUS_REQUEST,
            data: V2_OCSP_DATA,
        },
    ];
    assert_eq!(
        select_status_request(&extensions).err(),
        Some(Tls12Error::DuplicateExtension)
    );
}

#[test]
fn rfc_derived_legacy_and_v2_never_both_acknowledged() {
    let mut block = vec![0x00, 0x05, 0x00, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00];
    block.extend_from_slice(V2_MULTI_BLOCK);
    let body = hello(&block);
    let parsed = parse_client_hello(&body).expect("parse ClientHello with both extensions");
    let selection = select_status_request(&parsed.extensions).expect("select status request");
    assert!(selection.legacy_status_request_offered);
    assert!(selection.ocsp_multi_usable);
    // The acknowledgement is only v2: the legacy extension is informational.
    assert_eq!(
        selection.server_hello_extension(),
        Some(STATUS_REQUEST_V2_ACK)
    );

    let legacy_only = [Extension {
        ext_type: STATUS_REQUEST,
        data: &[0x01, 0x00, 0x00, 0x00, 0x00][..],
    }];
    let selection = select_status_request(&legacy_only).expect("select legacy status request");
    assert!(selection.legacy_status_request_offered);
    assert_eq!(selection.server_hello_extension(), None);
}

#[test]
fn rfc_derived_truncated_and_oversized_nested_lengths_are_rejected() {
    let cases: &[(&[u8], Tls12Error)] = &[
        // Outer list length says 8, but only 7 bytes follow.
        (
            &[0x00, 0x08, 0x02, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00],
            Tls12Error::InvalidStatusRequest,
        ),
        // Item request_length says 5, but the outer list leaves only 4 bytes.
        (
            &[0x00, 0x07, 0x02, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00],
            Tls12Error::InvalidStatusRequest,
        ),
        // ResponderID list length says 4, but cannot be taken from the request.
        (
            &[0x00, 0x07, 0x02, 0x00, 0x04, 0x00, 0x04, 0x00, 0x00],
            Tls12Error::InvalidStatusRequest,
        ),
        // A zero-length ResponderID violates opaque ResponderID<1..2^16-1>.
        (
            &[0x00, 0x08, 0x02, 0x00, 0x05, 0x00, 0x02, 0x00, 0x00, 0x00],
            Tls12Error::InvalidStatusRequest,
        ),
        // A byte after the parsed OCSPStatusRequest breaks exact request_length.
        (
            &[0x00, 0x08, 0x02, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0xFF],
            Tls12Error::InvalidStatusRequest,
        ),
        (
            &[0x00, 0x07, 0x03, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00],
            Tls12Error::UnsupportedStatusType,
        ),
        (
            &[
                0x00, 0x0E, 0x02, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x04, 0x00, 0x00,
                0x00, 0x00,
            ],
            Tls12Error::DuplicateStatusType,
        ),
        (&[], Tls12Error::InvalidStatusRequest),
    ];
    for (data, expected) in cases {
        assert_eq!(
            parse_status_request_v2(data).err(),
            Some(*expected),
            "{data:?}"
        );
    }

    let mut trailing = hello(V2_MULTI_BLOCK);
    trailing.push(0xFF);
    assert_eq!(
        parse_client_hello(&trailing).err(),
        Some(Tls12Error::InvalidExtensions)
    );
    let mut long_session = hello(V2_MULTI_BLOCK);
    long_session[34] = 0x21;
    assert_eq!(
        parse_client_hello(&long_session).err(),
        Some(Tls12Error::InvalidSessionId)
    );
    let mut odd_suites = hello(V2_MULTI_BLOCK);
    odd_suites[36] = 0x03;
    assert_eq!(
        parse_client_hello(&odd_suites).err(),
        Some(Tls12Error::InvalidCipherSuites)
    );
    let mut no_compression = hello(V2_MULTI_BLOCK);
    no_compression[41] = 0x00;
    assert_eq!(
        parse_client_hello(&no_compression).err(),
        Some(Tls12Error::InvalidCompressionMethods)
    );
    let short = hello(V2_MULTI_BLOCK);
    assert_eq!(
        parse_client_hello(&short[..10]).err(),
        Some(Tls12Error::TruncatedClientHello)
    );
}

#[test]
fn rfc_derived_multi_status_body_has_ordered_responses_and_empty_slot() {
    let body = build_certificate_status_multi(
        3,
        &[
            OcspResponse::Der(&[0xAA, 0xBB, 0xCC]),
            OcspResponse::Missing,
            OcspResponse::Der(&[0xDD, 0xEE]),
        ],
    )
    .expect("build RFC-derived CertificateStatus body");
    assert_eq!(
        body,
        vec![
            0x02, 0x00, 0x00, 0x0E, // ocsp_multi, list length 14
            0x00, 0x00, 0x03, 0xAA, 0xBB, 0xCC, // certificate 1
            0x00, 0x00, 0x00, // certificate 2: empty staple
            0x00, 0x00, 0x02, 0xDD, 0xEE, // certificate 3
        ]
    );
    let message = wrap_handshake_message(CERTIFICATE_STATUS, &body).expect("wrap handshake body");
    assert_eq!(message[..4], [0x16, 0x00, 0x00, 0x12]);
    assert_eq!(&message[4..], body);

    assert_eq!(
        build_certificate_status_multi(1, &[OcspResponse::Missing]).expect("single empty slot"),
        vec![0x02, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00]
    );
    assert_eq!(
        build_certificate_status_multi(1, &[OcspResponse::Der(&[0xAA]), OcspResponse::Missing])
            .err(),
        Some(Tls12Error::TooManyResponses)
    );
    assert_eq!(
        build_certificate_status_multi(3, &[]).err(),
        Some(Tls12Error::InvalidCertificateStatus)
    );
    assert_eq!(
        build_certificate_status_multi(1, &[OcspResponse::Der(&[])]).err(),
        Some(Tls12Error::EmptyResponse)
    );
}

#[test]
fn rfc_derived_client_hello_reassembles_identically_across_three_fragments() {
    let body = hello(V2_MULTI_BLOCK);
    let message = wrap_handshake_message(0x01, &body).expect("wrap ClientHello");
    let expected = vec![HandshakeMessage {
        msg_type: 0x01,
        body: body.clone(),
    }];

    let mut one_record = HandshakeReassembler::new();
    assert_eq!(
        one_record
            .push_records(&record(&message))
            .expect("one record"),
        expected
    );
    one_record.finish().expect("one record is complete");

    // Split inside the four-byte handshake header and again inside the body.
    let fragments = [&message[..2], &message[2..33], &message[33..]];
    let mut reassembler = HandshakeReassembler::new();
    let mut reassembled = Vec::new();
    for fragment in fragments {
        reassembled.extend(
            reassembler
                .push_records(&record(fragment))
                .expect("fragment"),
        );
    }
    assert_eq!(reassembled, expected);
    reassembler.finish().expect("three records are complete");

    let from_one = parse_client_hello(&expected[0].body).expect("parse one-record ClientHello");
    let from_three =
        parse_client_hello(&reassembled[0].body).expect("parse fragmented ClientHello");
    assert_eq!(from_one, from_three);
}

#[test]
fn reassembler_rejects_bad_records_and_truncation() {
    let body = hello(V2_MULTI_BLOCK);
    let message = wrap_handshake_message(0x01, &body).expect("wrap ClientHello");

    let mut wrong_type = record(&message);
    wrong_type[0] = 0x17;
    let mut wrong_version = record(&message);
    wrong_version[2] = 0x04;
    let mut oversized = record(&message);
    oversized[3..5].copy_from_slice(&0x4001u16.to_be_bytes());
    let truncated = record(&message);
    for (input, expected) in [
        (&[0x16, 0x03, 0x03][..], Tls12Error::TruncatedRecord),
        (&wrong_type[..], Tls12Error::UnexpectedContentType),
        (&wrong_version[..], Tls12Error::InvalidRecordVersion),
        (&oversized[..], Tls12Error::RecordTooLarge),
        (
            &truncated[..truncated.len() - 1],
            Tls12Error::TruncatedRecord,
        ),
    ] {
        assert_eq!(
            HandshakeReassembler::new().push_records(input).err(),
            Some(expected)
        );
    }

    let mut small_budget = HandshakeReassembler::with_budget(10);
    assert_eq!(
        small_budget.push_records(&record(&message)).err(),
        Some(Tls12Error::BufferBudgetExceeded)
    );

    let mut incomplete = HandshakeReassembler::new();
    assert!(
        incomplete
            .push_records(&record(&message[..2]))
            .expect("first fragment")
            .is_empty()
    );
    assert_eq!(
        incomplete.finish().err(),
        Some(Tls12Error::TruncatedHandshake)
    );
    assert!(
        HandshakeReassembler::new()
            .push_records(&[])
            .expect("empty input")
            .is_empty()
    );
}
