use super::*;
use async_trait::async_trait;
use qid_core::models::{ScimGroup, ScimUser};
use std::sync::Mutex;

use crate::ENTERPRISE_USER_SCHEMA;

#[derive(Debug)]
struct RecordingTransport {
    status: u16,
    sent: Mutex<Vec<OutboundScimHttpRequest>>,
}

impl RecordingTransport {
    fn new(status: u16) -> Self {
        Self {
            status,
            sent: Mutex::new(Vec::new()),
        }
    }
}

#[async_trait]
impl OutboundScimTransport for RecordingTransport {
    async fn send(&self, request: OutboundScimHttpRequest) -> QidResult<OutboundScimHttpResponse> {
        self.sent
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(request);
        Ok(OutboundScimHttpResponse {
            status: self.status,
            body: Some(serde_json::json!({ "ok": true })),
        })
    }
}

fn local_user() -> ScimUser {
    ScimUser {
        id: "user-1".to_string(),
        realm_id: "corp".to_string(),
        external_id: Some("ext-1".to_string()),
        user_name: "alice@example.com".to_string(),
        name_json: serde_json::json!({ "formatted": "Alice Example" }),
        emails_json: serde_json::json!([
            { "value": "secondary@example.com" },
            { "value": "alice@example.com", "primary": true }
        ]),
        enterprise_json: serde_json::json!({
            "department": "Platform",
            "costCenter": "RND"
        }),
        directory_provider_id: None,
        deprovisioned_at: None,
        active: true,
    }
}

#[test]
fn outbound_mapping_renders_app_specific_scim_user() {
    let mut mapping = default_outbound_user_mapping();
    mapping.enterprise.insert(
        "costCenter".to_string(),
        OutboundAttributeSource::Enterprise("costCenter".to_string()),
    );
    mapping.enterprise.insert(
        "appRole".to_string(),
        OutboundAttributeSource::Constant(serde_json::Value::String("employee".to_string())),
    );

    let rendered = render_outbound_user(&local_user(), &mapping).unwrap();

    assert_eq!(rendered["userName"], "alice@example.com");
    assert_eq!(rendered["externalId"], "ext-1");
    assert_eq!(rendered["active"], true);
    assert_eq!(rendered["name"]["formatted"], "Alice Example");
    assert_eq!(rendered["emails"][0]["value"], "alice@example.com");
    assert_eq!(rendered[ENTERPRISE_USER_SCHEMA]["department"], "Platform");
    assert_eq!(rendered[ENTERPRISE_USER_SCHEMA]["costCenter"], "RND");
    assert_eq!(rendered[ENTERPRISE_USER_SCHEMA]["appRole"], "employee");
}

#[test]
fn outbound_plan_reports_create_replace_noop_and_drift() {
    let user = local_user();
    let mapping = default_outbound_user_mapping();
    let create_plan = plan_outbound_user_provisioning(&user, None, &mapping, true).unwrap();
    assert!(create_plan.dry_run);
    assert_eq!(create_plan.operation, OutboundOperation::Create);
    assert!(create_plan.drift.is_empty());

    let desired = render_outbound_user(&user, &mapping).unwrap();
    let noop_plan = plan_outbound_user_provisioning(&user, Some(&desired), &mapping, true).unwrap();
    assert_eq!(noop_plan.operation, OutboundOperation::Noop);
    assert!(noop_plan.drift.is_empty());

    let mut remote = desired;
    remote["id"] = serde_json::json!("user-1");
    remote["active"] = serde_json::Value::Bool(false);
    remote[ENTERPRISE_USER_SCHEMA]["department"] = serde_json::Value::String("Sales".to_string());
    let replace_plan =
        plan_outbound_user_provisioning(&user, Some(&remote), &mapping, true).unwrap();
    assert_eq!(replace_plan.operation, OutboundOperation::Replace);
    assert_eq!(
        replace_plan
            .drift
            .iter()
            .map(|item| item.path.as_str())
            .collect::<Vec<_>>(),
        vec![
            "active",
            "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User.department"
        ]
    );
}

#[test]
fn outbound_retry_policy_uses_capped_exponential_backoff() {
    let policy = OutboundRetryPolicy {
        max_attempts: 4,
        initial_delay_ms: 500,
        max_delay_ms: 2_000,
        multiplier: 3,
    };

    let first = plan_outbound_retry(&policy, 0, 10_000);
    assert_eq!(
        first,
        OutboundRetryDecision {
            attempt: 1,
            retry: true,
            delay_ms: Some(500),
            next_attempt_at_ms: Some(10_500),
        }
    );
    let capped = plan_outbound_retry(&policy, 2, 10_000);
    assert_eq!(capped.delay_ms, Some(2_000));
    assert_eq!(capped.next_attempt_at_ms, Some(12_000));

    let exhausted = plan_outbound_retry(&policy, 3, 10_000);
    assert_eq!(
        exhausted,
        OutboundRetryDecision {
            attempt: 4,
            retry: false,
            delay_ms: None,
            next_attempt_at_ms: None,
        }
    );
}

#[test]
fn outbound_execution_plan_combines_dry_run_drift_and_retry() {
    let user = local_user();
    let mapping = default_outbound_user_mapping();
    let mut remote = render_outbound_user(&user, &mapping).unwrap();
    remote["id"] = serde_json::json!("user-1");
    remote["active"] = serde_json::Value::Bool(false);

    let execution = plan_outbound_user_execution(
        &user,
        Some(&remote),
        &mapping,
        true,
        default_outbound_retry_policy(),
        1,
        1_000,
    )
    .unwrap();

    assert!(execution.provisioning.dry_run);
    assert_eq!(execution.provisioning.operation, OutboundOperation::Replace);
    assert_eq!(execution.provisioning.drift[0].path, "active");
    assert_eq!(execution.retry_after_failure.attempt, 2);
    assert!(execution.retry_after_failure.retry);
    assert_eq!(execution.retry_after_failure.delay_ms, Some(2_000));
}

#[tokio::test]
async fn outbound_executor_sends_create_replace_and_skips_dry_run() {
    let user = local_user();
    let mapping = default_outbound_user_mapping();
    let config = OutboundScimClientConfig {
        base_url: "https://scim.example.com/scim/v2/".to_string(),
        bearer_token: Some("secret-token".to_string()),
    };

    let create_plan = plan_outbound_user_provisioning(&user, None, &mapping, false).unwrap();
    let transport = RecordingTransport::new(201);
    let result = execute_outbound_user_provisioning(&create_plan, &config, &transport)
        .await
        .unwrap();
    assert!(result.sent);
    assert_eq!(result.operation, OutboundOperation::Create);
    let request = result.request.unwrap();
    assert_eq!(request.method, "POST");
    assert_eq!(request.url, "https://scim.example.com/scim/v2/Users");
    assert_eq!(
        request.headers.get("Authorization").map(String::as_str),
        Some("Bearer secret-token")
    );
    assert_eq!(request.body.unwrap()["userName"], "alice@example.com");
    assert_eq!(
        transport
            .sent
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .len(),
        1
    );

    let mut remote = render_outbound_user(&user, &mapping).unwrap();
    remote["id"] = serde_json::json!("user-1");
    remote["active"] = serde_json::Value::Bool(false);
    let mut replace_plan =
        plan_outbound_user_provisioning(&user, Some(&remote), &mapping, false).unwrap();
    replace_plan.path = "/Users/user-1".to_string();
    let transport = RecordingTransport::new(200);
    let result = execute_outbound_user_provisioning(&replace_plan, &config, &transport)
        .await
        .unwrap();
    assert!(result.sent);
    let request = result.request.unwrap();
    assert_eq!(request.method, "PUT");
    assert_eq!(request.url, "https://scim.example.com/scim/v2/Users/user-1");

    let dry_run_plan = plan_outbound_user_provisioning(&user, None, &mapping, true).unwrap();
    let transport = RecordingTransport::new(201);
    let result = execute_outbound_user_provisioning(&dry_run_plan, &config, &transport)
        .await
        .unwrap();
    assert!(!result.sent);
    assert!(result.request.is_none());
    assert!(
        transport
            .sent
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_empty()
    );
}

#[tokio::test]
async fn outbound_executor_rejects_failed_status_and_invalid_config() {
    let user = local_user();
    let mapping = default_outbound_user_mapping();
    let plan = plan_outbound_user_provisioning(&user, None, &mapping, false).unwrap();
    let config = OutboundScimClientConfig {
        base_url: "https://scim.example.com/scim/v2".to_string(),
        bearer_token: None,
    };
    let transport = RecordingTransport::new(500);
    assert!(matches!(
        execute_outbound_user_provisioning(&plan, &config, &transport).await,
        Err(qid_core::error::QidError::BadRequest { .. })
    ));

    for base_url in ["", "http://scim.example/scim/v2"] {
        let invalid_config = OutboundScimClientConfig {
            base_url: base_url.to_string(),
            bearer_token: None,
        };
        assert!(matches!(
            build_outbound_scim_request(&plan, &invalid_config),
            Err(qid_core::error::QidError::BadRequest { .. })
        ));
    }
}

#[test]
fn outbound_orphan_cleanup_plans_dry_run_deactivate_and_delete() {
    let local = vec![local_user()];
    let remote = vec![
        serde_json::json!({
            "id": "remote-keep",
            "externalId": "ext-1",
            "userName": "alice@example.com",
            "active": true
        }),
        serde_json::json!({
            "id": "remote-orphan",
            "externalId": "ext-orphan",
            "userName": "orphan@example.com",
            "active": true
        }),
        serde_json::json!({
            "id": "remote-unmanaged",
            "userName": "unmanaged@example.com",
            "active": true
        }),
    ];
    let config = OutboundScimClientConfig {
        base_url: "https://app.example.com/scim/v2".to_string(),
        bearer_token: Some("secret".to_string()),
    };

    let dry_run = plan_outbound_orphan_cleanup(
        &local,
        &remote,
        &config,
        &default_outbound_orphan_cleanup_policy(),
    )
    .unwrap();
    assert_eq!(dry_run.len(), 1);
    assert!(dry_run[0].dry_run);
    assert_eq!(dry_run[0].external_id, "ext-orphan");
    assert_eq!(dry_run[0].remote_id, "remote-orphan");
    assert_eq!(dry_run[0].path, "/Users/remote-orphan");
    assert!(dry_run[0].request.is_none());

    let deactivate = plan_outbound_orphan_cleanup(
        &local,
        &remote,
        &config,
        &OutboundOrphanCleanupPolicy {
            dry_run: false,
            action: OutboundOrphanAction::Deactivate,
        },
    )
    .unwrap();
    let request = deactivate[0].request.as_ref().unwrap();
    assert_eq!(request.method, "PATCH");
    assert_eq!(
        request.url,
        "https://app.example.com/scim/v2/Users/remote-orphan"
    );
    assert_eq!(request.headers["Authorization"], "Bearer secret");
    assert_eq!(
        request.body.as_ref().unwrap()["Operations"][0],
        serde_json::json!({ "op": "replace", "path": "active", "value": false })
    );

    let delete = plan_outbound_orphan_cleanup(
        &local,
        &remote,
        &config,
        &OutboundOrphanCleanupPolicy {
            dry_run: false,
            action: OutboundOrphanAction::Delete,
        },
    )
    .unwrap();
    let request = delete[0].request.as_ref().unwrap();
    assert_eq!(request.method, "DELETE");
    assert_eq!(
        request.url,
        "https://app.example.com/scim/v2/Users/remote-orphan"
    );
    assert!(request.body.is_none());
}

#[test]
fn outbound_orphan_cleanup_rejects_remote_resource_without_id() {
    let local = vec![local_user()];
    let remote = vec![serde_json::json!({
        "externalId": "ext-orphan",
        "userName": "orphan@example.com"
    })];
    let config = OutboundScimClientConfig {
        base_url: "https://app.example.com/scim/v2".to_string(),
        bearer_token: None,
    };
    let result = plan_outbound_orphan_cleanup(
        &local,
        &remote,
        &config,
        &default_outbound_orphan_cleanup_policy(),
    );
    assert!(matches!(
        result,
        Err(qid_core::error::QidError::BadRequest { .. })
    ));
}

#[test]
fn outbound_group_entitlement_reconciliation_plans_create_replace_and_noop() {
    let group = ScimGroup {
        external_id: None,
        id: "group-1".to_string(),
        realm_id: "corp".to_string(),
        display_name: "app:erp:admin".to_string(),
        members_json: serde_json::json!([
            { "value": "user-1", "display": "alice@example.com" },
            { "value": "user-2", "display": "bob@example.com" }
        ]),
    };
    let config = OutboundScimClientConfig {
        base_url: "https://app.example.com/scim/v2".to_string(),
        bearer_token: None,
    };

    let create =
        plan_outbound_group_entitlement_reconciliation(&group, None, &config, false).unwrap();
    assert_eq!(create.operation, OutboundOperation::Create);
    assert_eq!(create.path, "/Groups");
    let create_request = create.request.as_ref().unwrap();
    assert_eq!(create_request.method, "POST");
    assert_eq!(create_request.url, "https://app.example.com/scim/v2/Groups");
    assert_eq!(
        create_request.body.as_ref().unwrap()["displayName"],
        "app:erp:admin"
    );

    let desired = serde_json::json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        "externalId": "group-1",
        "displayName": "app:erp:admin",
        "members": [
            { "value": "user-1", "display": "alice@example.com" },
            { "value": "user-2", "display": "bob@example.com" }
        ],
    });
    let noop =
        plan_outbound_group_entitlement_reconciliation(&group, Some(&desired), &config, false)
            .unwrap();
    assert_eq!(noop.operation, OutboundOperation::Noop);
    assert!(noop.drift.is_empty());
    assert!(noop.request.is_none());

    let mut remote = desired;
    remote["id"] = serde_json::Value::String("remote-group".to_string());
    remote["members"] = serde_json::json!([{ "value": "user-1" }]);
    let replace =
        plan_outbound_group_entitlement_reconciliation(&group, Some(&remote), &config, false)
            .unwrap();
    assert_eq!(replace.operation, OutboundOperation::Replace);
    assert_eq!(replace.path, "/Groups/remote-group");
    assert_eq!(
        replace
            .drift
            .iter()
            .map(|item| item.path.as_str())
            .collect::<Vec<_>>(),
        vec!["members"]
    );
    let replace_request = replace.request.as_ref().unwrap();
    assert_eq!(replace_request.method, "PUT");
    assert_eq!(
        replace_request.url,
        "https://app.example.com/scim/v2/Groups/remote-group"
    );

    let dry_run =
        plan_outbound_group_entitlement_reconciliation(&group, Some(&remote), &config, true)
            .unwrap();
    assert_eq!(dry_run.operation, OutboundOperation::Replace);
    assert!(dry_run.request.is_none());
}

#[test]
fn outbound_group_omitted_members_are_empty_for_reconciliation() {
    let mut group = ScimGroup {
        external_id: None,
        id: "group-1".into(),
        realm_id: "corp".into(),
        display_name: "app:erp:admin".into(),
        members_json: serde_json::json!([]),
    };
    let remote = serde_json::json!({
        "id": "remote-group",
        "externalId": group.id,
        "displayName": group.display_name,
    });
    let config = remote_config();
    let noop =
        plan_outbound_group_entitlement_reconciliation(&group, Some(&remote), &config, false)
            .unwrap();
    assert_eq!(noop.operation, OutboundOperation::Noop);
    assert!(noop.drift.is_empty());
    assert!(noop.request.is_none());

    group.members_json = serde_json::json!([{ "value": "user-1" }]);
    let replace =
        plan_outbound_group_entitlement_reconciliation(&group, Some(&remote), &config, false)
            .unwrap();
    assert_eq!(replace.operation, OutboundOperation::Replace);
    assert_eq!(replace.path, "/Groups/remote-group");
    assert_eq!(replace.drift.len(), 1);
    assert_eq!(replace.drift[0].path, "members");
    assert_eq!(replace.drift[0].desired, group.members_json);
    assert_eq!(replace.drift[0].remote, None);
    let request = replace.request.unwrap();
    assert_eq!(request.method, "PUT");
    assert_eq!(
        request.url,
        "https://scim.example/scim/v2/Groups/remote-group"
    );
    assert_eq!(request.body.unwrap()["members"], group.members_json);
}

#[test]
fn outbound_group_null_members_are_empty_for_reconciliation() {
    let mut group = ScimGroup {
        external_id: None,
        id: "group-1".into(),
        realm_id: "corp".into(),
        display_name: "app:erp:admin".into(),
        members_json: serde_json::json!([]),
    };
    let remote = serde_json::json!({
        "id": "remote-group",
        "externalId": group.id,
        "displayName": group.display_name,
        "members": null,
    });
    let config = remote_config();
    let noop =
        plan_outbound_group_entitlement_reconciliation(&group, Some(&remote), &config, false)
            .unwrap();
    assert_eq!(noop.operation, OutboundOperation::Noop);
    assert!(noop.drift.is_empty());

    group.members_json = serde_json::json!([{ "value": "user-1" }]);
    let replace =
        plan_outbound_group_entitlement_reconciliation(&group, Some(&remote), &config, false)
            .unwrap();
    assert_eq!(replace.operation, OutboundOperation::Replace);
    assert_eq!(replace.drift.len(), 1);
    assert_eq!(replace.drift[0].path, "members");
}

#[test]
fn outbound_group_reconciliation_rejects_malformed_members() {
    let mut group = ScimGroup {
        external_id: None,
        id: "group-1".into(),
        realm_id: "corp".into(),
        display_name: "app:erp:admin".into(),
        members_json: serde_json::json!([]),
    };
    let mut remote = serde_json::json!({
        "id": "remote-group",
        "externalId": group.id,
        "displayName": group.display_name,
    });
    for members in [
        serde_json::json!(false),
        serde_json::json!(1),
        serde_json::json!("user-1"),
        serde_json::json!({"value": "user-1"}),
        serde_json::json!([null]),
        serde_json::json!([{}]),
        serde_json::json!([{"value": ""}]),
        serde_json::json!([{"value": 1}]),
        serde_json::json!([{"value": "user-1"}, {"value": "user-1"}]),
    ] {
        group.members_json = serde_json::json!([]);
        remote["members"] = members.clone();
        assert!(
            matches!(
                plan_outbound_group_entitlement_reconciliation(
                    &group,
                    Some(&remote),
                    &remote_config(),
                    false
                ),
                Err(qid_core::error::QidError::BadRequest { .. })
            ),
            "accepted malformed remote members: {members}"
        );
        group.members_json = members.clone();
        assert!(
            matches!(
                plan_outbound_group_entitlement_reconciliation(
                    &group,
                    None,
                    &remote_config(),
                    false
                ),
                Err(qid_core::error::QidError::BadRequest { .. })
            ),
            "accepted malformed desired members: {members}"
        );
    }
}

struct ScriptedTransport {
    replies: Mutex<std::collections::VecDeque<OutboundScimHttpResponse>>,
    sent: Mutex<Vec<OutboundScimHttpRequest>>,
}
impl ScriptedTransport {
    fn new(bodies: Vec<serde_json::Value>) -> Self {
        Self {
            replies: Mutex::new(
                bodies
                    .into_iter()
                    .map(|body| OutboundScimHttpResponse {
                        status: 200,
                        body: Some(body),
                    })
                    .collect(),
            ),
            sent: Mutex::new(vec![]),
        }
    }
}
#[async_trait]
impl OutboundScimTransport for ScriptedTransport {
    async fn send(&self, request: OutboundScimHttpRequest) -> QidResult<OutboundScimHttpResponse> {
        self.sent.lock().unwrap().push(request);
        Ok(self
            .replies
            .lock()
            .unwrap()
            .pop_front()
            .expect("unexpected request"))
    }
}
fn list_page(total: usize, start: usize, resources: Vec<serde_json::Value>) -> serde_json::Value {
    serde_json::json!({"schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"], "totalResults": total, "startIndex": start, "itemsPerPage": resources.len(), "Resources": resources})
}
fn remote_config() -> OutboundScimClientConfig {
    OutboundScimClientConfig {
        base_url: "https://scim.example/scim/v2".into(),
        bearer_token: None,
    }
}
#[tokio::test]
async fn outbound_lookup_requires_complete_unambiguous_identity_and_safe_paths() {
    let external = "directory\\\" or active eq true";
    let remote = serde_json::json!({"id": "remote/id?x", "externalId": external});
    let transport = ScriptedTransport::new(vec![list_page(1, 1, vec![remote.clone()])]);
    assert_eq!(
        lookup_outbound_resource(&remote_config(), &transport, "Users", external)
            .await
            .unwrap(),
        Some(remote)
    );
    {
        let sent = transport.sent.lock().unwrap();
        let url = url::Url::parse(&sent[0].url).unwrap();
        let query: std::collections::BTreeMap<_, _> = url.query_pairs().into_owned().collect();
        assert_eq!(
            query["filter"],
            format!("externalId eq {}", serde_json::to_string(external).unwrap())
        );
        assert_eq!(query["startIndex"], "1");
        assert_eq!(query["count"], "2");
    }
    for body in [
        serde_json::json!({}),
        list_page(1, 1, vec![]),
        list_page(
            2,
            1,
            vec![serde_json::json!({"id":"a", "externalId": external})],
        ),
        list_page(
            1,
            2,
            vec![serde_json::json!({"id":"a", "externalId": external})],
        ),
        list_page(1, 1, vec![serde_json::json!({"externalId": external})]),
        list_page(
            1,
            1,
            vec![serde_json::json!({"id":"a", "externalId": "wrong"})],
        ),
    ] {
        assert!(
            lookup_outbound_resource(
                &remote_config(),
                &ScriptedTransport::new(vec![body]),
                "Users",
                external
            )
            .await
            .is_err()
        );
    }
    assert!(
        lookup_outbound_resource(
            &remote_config(),
            &ScriptedTransport::new(vec![list_page(0, 1, vec![])]),
            "Users",
            external
        )
        .await
        .unwrap()
        .is_none()
    );
    let mut user = local_user();
    user.external_id = None;
    user.deprovisioned_at = Some(12);
    let desired = render_outbound_user(&user, &default_outbound_user_mapping()).unwrap();
    assert_eq!(desired["externalId"], user.id);
    assert_eq!(desired["active"], false);
    let mut remote = desired.clone();
    remote["id"] = serde_json::json!("remote/id?x");
    remote["active"] = serde_json::json!(true);
    let plan = plan_outbound_user_provisioning(
        &user,
        Some(&remote),
        &default_outbound_user_mapping(),
        false,
    )
    .unwrap();
    assert_eq!(plan.path, "/Users/remote%2Fid%3Fx");
    assert_eq!(
        build_outbound_scim_request(&plan, &remote_config())
            .unwrap()
            .unwrap()
            .method,
        "PUT"
    );
    remote.as_object_mut().unwrap().remove("id");
    assert!(
        plan_outbound_user_provisioning(
            &user,
            Some(&remote),
            &default_outbound_user_mapping(),
            false
        )
        .is_err()
    );
}
#[tokio::test]
async fn outbound_inventory_is_bounded_and_group_membership_is_order_independent() {
    let a = serde_json::json!({"id":"a", "externalId":"ea"});
    let b = serde_json::json!({"id":"b", "externalId":"eb"});
    let limits = OutboundInventoryLimits {
        page_size: 1,
        max_resources: 2,
    };
    let transport = ScriptedTransport::new(vec![
        list_page(2, 1, vec![a.clone()]),
        list_page(2, 2, vec![b.clone()]),
    ]);
    assert_eq!(
        list_outbound_resources(&remote_config(), &transport, "Users", &limits)
            .await
            .unwrap()
            .len(),
        2
    );
    assert!(
        transport.sent.lock().unwrap()[1]
            .url
            .ends_with("startIndex=2&count=1")
    );
    for pages in [
        vec![list_page(3, 1, vec![a.clone()])],
        vec![
            list_page(2, 1, vec![a.clone()]),
            list_page(2, 2, vec![a.clone()]),
        ],
        vec![list_page(2, 1, vec![a.clone()]), list_page(1, 2, vec![])],
        vec![list_page(2, 1, vec![])],
        vec![list_page(2, 1, vec![a.clone(), b.clone()])],
        vec![
            list_page(2, 1, vec![a.clone()]),
            list_page(2, 2, vec![serde_json::json!({"id":"b","externalId":"ea"})]),
        ],
    ] {
        assert!(
            list_outbound_resources(
                &remote_config(),
                &ScriptedTransport::new(pages),
                "Users",
                &limits
            )
            .await
            .is_err()
        );
    }
    let group = ScimGroup {
        external_id: None,
        id: "g".into(),
        realm_id: "corp".into(),
        display_name: "renamed".into(),
        members_json: serde_json::json!([{"value":"a"},{"value":"b"}]),
    };
    let remote = serde_json::json!({"id":"remote-g", "externalId":"g", "displayName":"renamed", "members":[{"value":"b", "display":"Bob"},{"value":"a"}]});
    assert_eq!(
        plan_outbound_group_entitlement_reconciliation(
            &group,
            Some(&remote),
            &remote_config(),
            false
        )
        .unwrap()
        .operation,
        OutboundOperation::Noop
    );
    let user = ScimUser {
        external_id: None,
        ..local_user()
    };
    assert!(
        plan_outbound_orphan_cleanup(
            std::slice::from_ref(&user),
            &[serde_json::json!({"id":"r","externalId":user.id})],
            &remote_config(),
            &default_outbound_orphan_cleanup_policy()
        )
        .unwrap()
        .is_empty()
    );
}
