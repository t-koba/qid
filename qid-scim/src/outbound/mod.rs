//! Outbound SCIM provisioning.

mod execution;
mod mapping;
mod orphan;
mod reconcile;
mod transport;

pub use execution::{
    OutboundProvisioningExecutionPlan, build_outbound_scim_request,
    execute_outbound_user_provisioning, plan_outbound_retry, plan_outbound_user_execution,
};
pub use mapping::{
    OutboundAttributeSource, OutboundUserMapping, default_outbound_user_mapping,
    plan_outbound_user_provisioning, render_outbound_user,
};
pub use orphan::{
    OutboundOrphanAction, OutboundOrphanCleanupPlan, OutboundOrphanCleanupPolicy,
    default_outbound_orphan_cleanup_policy, plan_outbound_orphan_cleanup,
};
pub use reconcile::{
    OutboundGroupReconciliationPlan, plan_outbound_group_entitlement_reconciliation,
};
pub use transport::{OutboundScimTransport, ReqwestOutboundScimTransport};

use qid_core::error::QidResult;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum OutboundOperation {
    Create,
    Replace,
    Noop,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OutboundDrift {
    pub path: String,
    pub desired: serde_json::Value,
    pub remote: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OutboundProvisioningPlan {
    pub dry_run: bool,
    pub operation: OutboundOperation,
    pub path: String,
    pub desired: serde_json::Value,
    pub drift: Vec<OutboundDrift>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OutboundRetryPolicy {
    pub max_attempts: u32,
    pub initial_delay_ms: u64,
    pub max_delay_ms: u64,
    pub multiplier: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OutboundRetryDecision {
    pub attempt: u32,
    pub retry: bool,
    pub delay_ms: Option<u64>,
    pub next_attempt_at_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OutboundScimClientConfig {
    pub base_url: String,
    pub bearer_token: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OutboundScimHttpRequest {
    pub method: String,
    pub url: String,
    pub headers: std::collections::BTreeMap<String, String>,
    pub body: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OutboundScimHttpResponse {
    pub status: u16,
    pub body: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OutboundProvisioningResult {
    pub operation: OutboundOperation,
    pub dry_run: bool,
    pub sent: bool,
    pub request: Option<OutboundScimHttpRequest>,
    pub response: Option<OutboundScimHttpResponse>,
}

pub fn default_outbound_retry_policy() -> OutboundRetryPolicy {
    OutboundRetryPolicy {
        max_attempts: 5,
        initial_delay_ms: 1_000,
        max_delay_ms: 60_000,
        multiplier: 2,
    }
}

pub(crate) fn join_scim_url(base_url: &str, path: &str) -> QidResult<String> {
    if base_url.trim().is_empty() {
        return Err(qid_core::error::QidError::BadRequest {
            message: "outbound SCIM base_url must not be empty".to_string(),
        });
    }
    let base = base_url.trim_end_matches('/');
    let path = if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{path}")
    };
    Ok(format!("{base}{path}"))
}

pub(crate) fn scim_success_status(operation: &OutboundOperation, status: u16) -> bool {
    match operation {
        OutboundOperation::Create => matches!(status, 200 | 201),
        OutboundOperation::Replace => matches!(status, 200 | 204),
        OutboundOperation::Noop => true,
    }
}

pub(crate) fn scim_operation_name(operation: &OutboundOperation) -> &'static str {
    match operation {
        OutboundOperation::Create => "create",
        OutboundOperation::Replace => "replace",
        OutboundOperation::Noop => "noop",
    }
}

pub(crate) fn collect_drift(
    path: &str,
    segments: &[&str],
    desired: &serde_json::Value,
    remote: &serde_json::Value,
    drift: &mut Vec<OutboundDrift>,
) {
    let Some(desired_value) = get_path(desired, segments) else {
        return;
    };
    let remote_value = get_path(remote, segments);
    if remote_value != Some(desired_value.clone()) {
        drift.push(OutboundDrift {
            path: path.to_string(),
            desired: desired_value,
            remote: remote_value,
        });
    }
}

pub(crate) fn get_path(value: &serde_json::Value, segments: &[&str]) -> Option<serde_json::Value> {
    let mut current = value;
    for segment in segments {
        current = if let Ok(index) = segment.parse::<usize>() {
            current.as_array()?.get(index)?
        } else {
            current.get(*segment)?
        };
    }
    Some(current.clone())
}

#[cfg(test)]
mod tests {
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
        async fn send(
            &self,
            request: OutboundScimHttpRequest,
        ) -> QidResult<OutboundScimHttpResponse> {
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
        let noop_plan =
            plan_outbound_user_provisioning(&user, Some(&desired), &mapping, true).unwrap();
        assert_eq!(noop_plan.operation, OutboundOperation::Noop);
        assert!(noop_plan.drift.is_empty());

        let mut remote = desired;
        remote["active"] = serde_json::Value::Bool(false);
        remote[ENTERPRISE_USER_SCHEMA]["department"] =
            serde_json::Value::String("Sales".to_string());
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

        let invalid_config = OutboundScimClientConfig {
            base_url: "".to_string(),
            bearer_token: None,
        };
        assert!(matches!(
            build_outbound_scim_request(&plan, &invalid_config),
            Err(qid_core::error::QidError::BadRequest { .. })
        ));
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
        assert_eq!(
            create.path,
            "/Groups?filter=displayName eq \"app:erp:admin\""
        );
        let create_request = create.request.as_ref().unwrap();
        assert_eq!(create_request.method, "POST");
        assert_eq!(create_request.url, "https://app.example.com/scim/v2/Groups");
        assert_eq!(
            create_request.body.as_ref().unwrap()["displayName"],
            "app:erp:admin"
        );

        let desired = serde_json::json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
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
}
