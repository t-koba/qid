use axum::http::{HeaderMap, HeaderValue, header::COOKIE};
use qid_http::{combined_cookie_header, extract_cookie, parse_cookie};

#[test]
fn cookie_extraction_preserves_exact_name_and_opaque_value() {
    let mut headers = HeaderMap::new();
    assert_eq!(extract_cookie(&headers, "session"), None);
    headers.insert(
        COOKIE,
        "session-other=no; broken; session = a=b%20 "
            .parse()
            .unwrap(),
    );
    // A spaced name is not an RFC 6265 token and must not normalize to `session`.
    assert_eq!(extract_cookie(&headers, "session"), None);
    assert_eq!(extract_cookie(&headers, "missing"), None);
    headers.insert(COOKIE, "session= ".parse().unwrap());
    assert_eq!(extract_cookie(&headers, "session"), Some(String::new()));
    headers.insert(COOKIE, HeaderValue::from_bytes(b"session=\xff").unwrap());
    assert_eq!(extract_cookie(&headers, "session"), None);
}

#[test]
fn duplicate_cookie_names_fail_closed() {
    let header = "qid_session=sid_attacker; qid_session=sid_victim; theme=dark";
    assert_eq!(parse_cookie(header, "qid_session"), None);
    assert_eq!(parse_cookie(header, "theme"), Some("dark".into()));

    let mut headers = HeaderMap::new();
    headers.insert(COOKIE, header.parse().unwrap());
    assert_eq!(extract_cookie(&headers, "qid_session"), None);
    assert_eq!(extract_cookie(&headers, "theme"), Some("dark".into()));

    // A non-token spelling is ignored rather than normalized into the name.
    assert_eq!(
        parse_cookie("qid_session=a; qid_session =b", "qid_session"),
        Some("a".into())
    );

    // Unicode whitespace can make a browser-non-prefixed cookie normalize to
    // a configured __Host- name; such names must never be read by qid.
    assert_eq!(
        parse_cookie(
            "\u{2000}__Host-qid-federation-tx=attacker",
            "__Host-qid-federation-tx"
        ),
        None
    );
}

#[test]
fn cookies_split_across_headers_are_combined() {
    let mut headers = HeaderMap::new();
    assert_eq!(combined_cookie_header(&headers), None);

    headers.append(COOKIE, "theme=dark".parse().unwrap());
    headers.append(COOKIE, "qid_session=sid".parse().unwrap());
    assert_eq!(
        combined_cookie_header(&headers).as_deref(),
        Some("theme=dark; qid_session=sid")
    );
    assert_eq!(extract_cookie(&headers, "theme"), Some("dark".into()));
    assert_eq!(extract_cookie(&headers, "qid_session"), Some("sid".into()));

    // The duplicate spans headers, so only a combined view can fail closed.
    headers.append(COOKIE, "qid_session=attacker".parse().unwrap());
    assert_eq!(extract_cookie(&headers, "qid_session"), None);
    assert_eq!(extract_cookie(&headers, "theme"), Some("dark".into()));

    headers.append(COOKIE, HeaderValue::from_bytes(b"broken=\xff").unwrap());
    assert_eq!(combined_cookie_header(&headers), None);
    assert_eq!(extract_cookie(&headers, "theme"), None);
}
