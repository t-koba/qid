use axum::http::{HeaderMap, HeaderValue, header::COOKIE};
use qid_http::extract_cookie;

#[test]
fn cookie_extraction_preserves_first_exact_name_and_opaque_value() {
    let mut headers = HeaderMap::new();
    assert_eq!(extract_cookie(&headers, "session"), None);
    headers.insert(
        COOKIE,
        "session-other=no; broken; session = a=b%20 ; session=second"
            .parse()
            .unwrap(),
    );
    assert_eq!(extract_cookie(&headers, "session"), Some("a=b%20".into()));
    assert_eq!(extract_cookie(&headers, "missing"), None);
    headers.insert(COOKIE, "session= ".parse().unwrap());
    assert_eq!(extract_cookie(&headers, "session"), Some(String::new()));
    headers.insert(COOKIE, HeaderValue::from_bytes(b"session=\xff").unwrap());
    assert_eq!(extract_cookie(&headers, "session"), None);
}
