use qid_crypto::jwk::matching_jwk_candidates;
use serde_json::json;

#[test]
fn optional_kid_matches_exactly_and_missing_kid_keeps_all_candidates() {
    let keys = vec![
        json!({"kid": "selected"}),
        json!({"kid": "other"}),
        json!({}),
        json!({"kid": 7}),
    ];

    let selected = matching_jwk_candidates(&keys, Some("selected"));
    assert_eq!(selected, vec![&keys[0]]);
    assert_eq!(matching_jwk_candidates(&keys, None).len(), keys.len());
}
