use qid_policy::{Expression, PolicyBundle};

fn bundle_with_expression(expression: serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "version": "1",
        "default_decision": "deny",
        "rules": [{
            "name": "rule-under-test",
            "type": "allow",
            "action": "read",
            "expression": expression
        }]
    })
}

fn parse(bundle: serde_json::Value) -> Result<PolicyBundle, String> {
    serde_json::from_value::<PolicyBundle>(bundle).map_err(|error| error.to_string())
}

#[test]
fn an_unknown_key_inside_an_expression_is_rejected_by_name() {
    let error = parse(bundle_with_expression(serde_json::json!({
        "and": [{"field": "acr", "op": "equals", "value": "high"}],
        "or": []
    })))
    .expect_err("a mixed operator bundle is rejected");

    assert!(
        error.contains("mixes `and` with `or`"),
        "the error must name both operators: {error}"
    );
}

#[test]
fn an_unknown_key_in_an_expression_is_rejected_by_name() {
    let error = parse(bundle_with_expression(serde_json::json!({
        "not": {"field": "acr", "op": "equals", "value": "high"},
        "negate": true
    })))
    .expect_err("an unknown expression key is rejected");

    assert!(
        error.contains("unknown key `negate`"),
        "the error must name the unknown key: {error}"
    );
}

#[test]
fn a_malformed_operator_bundle_names_the_offending_key() {
    let error = parse(bundle_with_expression(serde_json::json!({"and": "high"})))
        .expect_err("a malformed operator bundle is rejected");
    assert!(
        error.contains("key `and` must be a list"),
        "the error must name the key and its expected shape: {error}"
    );

    let error = parse(bundle_with_expression(serde_json::json!({
        "and": [{"field": "acr", "op": "equals"}]
    })))
    .expect_err("a malformed operator entry is rejected");
    assert!(
        error.contains("entry 0") && error.contains("missing key `value`"),
        "the error must locate the faulty entry: {error}"
    );

    let error = parse(bundle_with_expression(serde_json::json!({"in_group": 7})))
        .expect_err("a wrong value type is rejected");
    assert!(
        error.contains("key `in_group` must be a string"),
        "the error must name the key and its expected type: {error}"
    );
}

#[test]
fn a_rule_with_an_unknown_key_is_rejected_instead_of_becoming_unconditional() {
    // A misspelled `conditions` key used to be ignored, which left the allow
    // rule with no conditions at all and made it match every request.
    let error = parse(serde_json::json!({
        "version": "1",
        "default_decision": "deny",
        "rules": [{
            "name": "allow-admin",
            "type": "allow",
            "action": "read",
            "condition": [{"field": "acr", "op": "equals", "value": "high"}]
        }]
    }))
    .expect_err("an unknown rule key is rejected");

    assert!(
        error.contains("unknown field `condition`"),
        "the error must name the unknown rule key: {error}"
    );
}

#[test]
fn a_rule_with_an_unknown_condition_key_is_rejected() {
    let error = parse(serde_json::json!({
        "version": "1",
        "default_decision": "deny",
        "rules": [{
            "name": "allow-admin",
            "type": "allow",
            "action": "read",
            "conditions": [{"field": "acr", "op": "equals", "value": "high", "negate": true}]
        }]
    }))
    .expect_err("an unknown condition key is rejected");

    assert!(
        error.contains("unknown field `negate`"),
        "the error must name the unknown condition key: {error}"
    );
}

#[test]
fn the_supported_expression_shapes_still_load() {
    let bundle = parse(bundle_with_expression(serde_json::json!({
        "not": {"field": "acr", "op": "equals", "value": "high"}
    })))
    .expect("a condition expression loads");
    assert!(matches!(
        bundle.rules[0].expression,
        Some(Expression::Not { .. })
    ));

    parse(bundle_with_expression(serde_json::json!({
        "and": [{"field": "acr", "op": "equals", "value": "high"}],
        "or": []
    })))
    .expect_err("a mixed operator bundle is still rejected");

    let bundle = parse(serde_json::json!({
        "version": "1",
        "default_decision": "deny",
        "rules": [{
            "name": "allow-admin",
            "type": "allow",
            "action": "read",
            "conditions": [{"field": "acr", "op": "equals", "value": "high"}],
            "resource_host": "*.finance.example.com",
            "expression": {
                "not": {"field": "subject_id", "op": "equals", "value": ""}
            }
        }]
    }))
    .expect("a full rule loads");
    assert_eq!(bundle.rules.len(), 1);
    assert_eq!(bundle.rules[0].conditions.len(), 1);
}
