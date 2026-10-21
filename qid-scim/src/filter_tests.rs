use crate::filter::{parse_eq_filter, string_filter_matches};

#[test]
fn a_quoted_value_may_contain_operator_words() {
    let filter = parse_eq_filter(
        "displayName eq \"Research and Development\"",
        &["displayName"],
    )
    .expect("a quoted value is accepted");
    assert_eq!(filter.attribute, "displayName");
    assert!(string_filter_matches(
        &filter.value,
        "Research and Development"
    ));
}

#[test]
fn a_quoted_value_may_contain_a_prefix_operator_word() {
    let filter = parse_eq_filter("displayName eq \"a pr b\"", &["displayName"])
        .expect("a quoted value is accepted");
    assert!(string_filter_matches(&filter.value, "a pr b"));
}

#[test]
fn a_compound_filter_is_rejected() {
    let error = parse_eq_filter(
        "displayName eq \"a\" and userName eq \"b\"",
        &["displayName", "userName"],
    )
    .expect_err("a compound filter is rejected");
    assert!(error.message().contains("unsupported SCIM filter operator"));
}

#[test]
fn a_filter_over_the_length_cap_is_rejected() {
    let filter = format!("displayName eq \"{}\"", "a".repeat(2100));
    let error =
        parse_eq_filter(&filter, &["displayName"]).expect_err("an over-long filter is rejected");
    assert!(error.message().contains("maximum length"));
}
