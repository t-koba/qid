use qid_core::{error::QidResult, models::ScimUser};
use std::collections::BTreeMap;

use super::mapping::plan_outbound_user_provisioning;
use super::{
    OutboundOperation, OutboundProvisioningPlan, OutboundProvisioningResult, OutboundRetryDecision,
    OutboundRetryPolicy, OutboundScimClientConfig, OutboundScimHttpRequest, OutboundScimTransport,
    OutboundUserMapping, join_scim_url, scim_operation_name, scim_success_status,
};

pub struct OutboundProvisioningExecutionPlan {
    pub provisioning: OutboundProvisioningPlan,
    pub retry_policy: OutboundRetryPolicy,
    pub retry_after_failure: OutboundRetryDecision,
}

pub fn plan_outbound_retry(
    policy: &OutboundRetryPolicy,
    completed_attempts: u32,
    now_ms: u64,
) -> OutboundRetryDecision {
    let attempt = completed_attempts.saturating_add(1);
    if attempt >= policy.max_attempts || policy.max_attempts == 0 {
        return OutboundRetryDecision {
            attempt,
            retry: false,
            delay_ms: None,
            next_attempt_at_ms: None,
        };
    }
    let exponent = completed_attempts.min(31);
    let factor = u64::from(policy.multiplier).saturating_pow(exponent);
    let delay = policy
        .initial_delay_ms
        .saturating_mul(factor)
        .min(policy.max_delay_ms);
    OutboundRetryDecision {
        attempt,
        retry: true,
        delay_ms: Some(delay),
        next_attempt_at_ms: Some(now_ms.saturating_add(delay)),
    }
}

pub fn plan_outbound_user_execution(
    user: &ScimUser,
    remote: Option<&serde_json::Value>,
    mapping: &OutboundUserMapping,
    dry_run: bool,
    retry_policy: OutboundRetryPolicy,
    completed_attempts: u32,
    now_ms: u64,
) -> QidResult<OutboundProvisioningExecutionPlan> {
    Ok(OutboundProvisioningExecutionPlan {
        provisioning: plan_outbound_user_provisioning(user, remote, mapping, dry_run)?,
        retry_after_failure: plan_outbound_retry(&retry_policy, completed_attempts, now_ms),
        retry_policy,
    })
}

pub fn build_outbound_scim_request(
    plan: &OutboundProvisioningPlan,
    config: &OutboundScimClientConfig,
) -> QidResult<Option<OutboundScimHttpRequest>> {
    if plan.dry_run || plan.operation == OutboundOperation::Noop {
        return Ok(None);
    }
    let (method, path, body) = match plan.operation {
        OutboundOperation::Create => ("POST", "/Users", Some(plan.desired.clone())),
        OutboundOperation::Replace => ("PUT", plan.path.as_str(), Some(plan.desired.clone())),
        OutboundOperation::Noop => {
            return Err(qid_core::error::QidError::Internal {
                message: "unexpected Noop operation".to_string(),
            });
        }
    };
    let mut headers = BTreeMap::from([
        ("Accept".to_string(), "application/scim+json".to_string()),
        (
            "Content-Type".to_string(),
            "application/scim+json".to_string(),
        ),
    ]);
    if let Some(token) = &config.bearer_token {
        headers.insert("Authorization".to_string(), format!("Bearer {token}"));
    }
    Ok(Some(OutboundScimHttpRequest {
        method: method.to_string(),
        url: join_scim_url(&config.base_url, path)?,
        headers,
        body,
    }))
}

pub async fn execute_outbound_user_provisioning<T: OutboundScimTransport>(
    plan: &OutboundProvisioningPlan,
    config: &OutboundScimClientConfig,
    transport: &T,
) -> QidResult<OutboundProvisioningResult> {
    let request = build_outbound_scim_request(plan, config)?;
    let Some(request) = request else {
        return Ok(OutboundProvisioningResult {
            operation: plan.operation.clone(),
            dry_run: plan.dry_run,
            sent: false,
            request: None,
            response: None,
        });
    };
    let response = transport.send(request.clone()).await?;
    if !scim_success_status(&plan.operation, response.status) {
        return Err(qid_core::error::QidError::BadRequest {
            message: format!(
                "outbound SCIM {} failed with status {}",
                scim_operation_name(&plan.operation),
                response.status
            ),
        });
    }
    Ok(OutboundProvisioningResult {
        operation: plan.operation.clone(),
        dry_run: plan.dry_run,
        sent: true,
        request: Some(request),
        response: Some(response),
    })
}
