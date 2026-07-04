use crate::{bad_request, sha256_hex};
use qid_core::error::QidResult;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClusterNode {
    pub id: String,
    pub region: String,
    pub priority: u32,
    pub last_seen_epoch: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LeaderLease {
    pub leader_id: String,
    pub term: u64,
    pub expires_at_epoch: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TenantShard {
    pub id: String,
    pub region: String,
    pub weight: u32,
    pub writable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TenantShardPlan {
    pub status: TenantShardPlanStatus,
    pub tenant_id: String,
    pub primary_shard_id: Option<String>,
    pub primary_region: Option<String>,
    pub replica_shard_ids: Vec<String>,
    pub routing_key: Option<String>,
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TenantShardPlanStatus {
    Ready,
    Rejected,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ActiveActiveTopologyPlan {
    pub status: ActiveActiveTopologyStatus,
    pub shard_count: usize,
    pub region_count: usize,
    pub writable_shard_count: usize,
    pub writable_region_count: usize,
    pub required_region_count: usize,
    pub required_replica_count: usize,
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ActiveActiveTopologyStatus {
    Ready,
    Rejected,
}

pub fn plan_active_active_topology(
    shards: &[TenantShard],
    required_region_count: usize,
    required_replica_count: usize,
) -> ActiveActiveTopologyPlan {
    let mut reasons = validate_tenant_shards(shards);
    if shards.is_empty() {
        reasons.push("empty_shard_set".to_string());
    }
    if required_region_count < 2 {
        reasons.push("required_region_count_below_active_active_minimum".to_string());
    }

    let region_count = shards
        .iter()
        .filter(|shard| !shard.region.trim().is_empty())
        .map(|shard| shard.region.as_str())
        .collect::<BTreeSet<_>>()
        .len();
    let writable_regions = shards
        .iter()
        .filter(|shard| shard.writable && shard.weight > 0 && !shard.region.trim().is_empty())
        .map(|shard| shard.region.as_str())
        .collect::<BTreeSet<_>>();
    let writable_region_count = writable_regions.len();
    let writable_shard_count = shards
        .iter()
        .filter(|shard| shard.writable && shard.weight > 0)
        .count();

    if region_count < required_region_count {
        reasons.push(format!(
            "insufficient_regions:{region_count}/{required_region_count}"
        ));
    }
    if writable_region_count < required_region_count {
        reasons.push(format!(
            "insufficient_writable_regions:{writable_region_count}/{required_region_count}"
        ));
    }
    if writable_shard_count == 0 {
        reasons.push("no_writable_shard".to_string());
    }

    let minimum_shards = required_replica_count.saturating_add(1);
    if shards.len() < minimum_shards {
        reasons.push(format!(
            "insufficient_shards_for_replicas:{}/{}",
            shards.len(),
            minimum_shards
        ));
    }
    if required_replica_count > 0 {
        let has_cross_region_replica = shards.iter().any(|primary| {
            primary.writable
                && primary.weight > 0
                && shards.iter().any(|replica| {
                    replica.id != primary.id
                        && replica.weight > 0
                        && !replica.region.trim().is_empty()
                        && replica.region != primary.region
                })
        });
        if !has_cross_region_replica {
            reasons.push("cross_region_replica_unavailable".to_string());
        }
    }

    let status = if reasons.is_empty() {
        ActiveActiveTopologyStatus::Ready
    } else {
        ActiveActiveTopologyStatus::Rejected
    };

    ActiveActiveTopologyPlan {
        status,
        shard_count: shards.len(),
        region_count,
        writable_shard_count,
        writable_region_count,
        required_region_count,
        required_replica_count,
        reasons,
    }
}

pub fn plan_tenant_shard(
    tenant_id: &str,
    shards: &[TenantShard],
    preferred_region: Option<&str>,
    replica_count: usize,
) -> TenantShardPlan {
    let tenant_id = tenant_id.trim();
    let preferred_region = preferred_region
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let mut reasons = Vec::new();
    if tenant_id.is_empty() {
        reasons.push("empty_tenant_id".to_string());
    }
    if shards.is_empty() {
        reasons.push("empty_shard_set".to_string());
    }

    reasons.extend(validate_tenant_shards(shards));

    let candidate_shards = candidate_shards(shards, preferred_region);
    if candidate_shards.is_empty() {
        reasons.push(match preferred_region {
            Some(region) => format!("no_writable_shard_in_preferred_region:{region}"),
            None => "no_writable_shard".to_string(),
        });
    }

    if reasons.iter().any(|reason| {
        reason == "empty_tenant_id"
            || reason == "empty_shard_set"
            || reason == "no_writable_shard"
            || reason.starts_with("no_writable_shard_in_preferred_region:")
            || reason.starts_with("empty_shard_id")
            || reason.starts_with("shard_region_empty:")
            || reason.starts_with("shard_weight_zero:")
            || reason.starts_with("duplicate_shard_id:")
    }) {
        return TenantShardPlan {
            status: TenantShardPlanStatus::Rejected,
            tenant_id: tenant_id.to_string(),
            primary_shard_id: None,
            primary_region: None,
            replica_shard_ids: Vec::new(),
            routing_key: None,
            reasons,
        };
    }

    let primary = candidate_shards
        .into_iter()
        .max_by_key(|shard| tenant_shard_score(tenant_id, shard))
        .expect("candidate_shards is not empty");
    let replica_shard_ids = replica_shards(tenant_id, shards, &primary.id, replica_count);
    TenantShardPlan {
        status: TenantShardPlanStatus::Ready,
        tenant_id: tenant_id.to_string(),
        primary_shard_id: Some(primary.id.clone()),
        primary_region: Some(primary.region.clone()),
        replica_shard_ids,
        routing_key: Some(format!("tenant:{tenant_id}:shard:{}", primary.id)),
        reasons,
    }
}

fn candidate_shards<'a>(
    shards: &'a [TenantShard],
    preferred_region: Option<&str>,
) -> Vec<&'a TenantShard> {
    let writable = shards
        .iter()
        .filter(|shard| shard.writable && shard.weight > 0)
        .collect::<Vec<_>>();
    if let Some(region) = preferred_region {
        return writable
            .into_iter()
            .filter(|shard| shard.region == region)
            .collect();
    }
    writable
}

fn replica_shards(
    tenant_id: &str,
    shards: &[TenantShard],
    primary_shard_id: &str,
    replica_count: usize,
) -> Vec<String> {
    let mut candidates = shards
        .iter()
        .filter(|shard| shard.id != primary_shard_id && shard.weight > 0)
        .map(|shard| (tenant_shard_score(tenant_id, shard), shard.id.clone()))
        .collect::<Vec<_>>();
    candidates.sort_by(|left, right| right.0.cmp(&left.0).then_with(|| left.1.cmp(&right.1)));
    candidates
        .into_iter()
        .take(replica_count)
        .map(|(_, id)| id)
        .collect()
}

fn validate_tenant_shards(shards: &[TenantShard]) -> Vec<String> {
    let mut reasons = Vec::new();
    let mut seen_ids = BTreeMap::new();
    for shard in shards {
        if shard.id.trim().is_empty() {
            reasons.push("empty_shard_id".to_string());
        }
        if shard.region.trim().is_empty() {
            reasons.push(format!("shard_region_empty:{}", shard.id));
        }
        if shard.weight == 0 {
            reasons.push(format!("shard_weight_zero:{}", shard.id));
        }
        if seen_ids.insert(shard.id.as_str(), ()).is_some() {
            reasons.push(format!("duplicate_shard_id:{}", shard.id));
        }
    }
    reasons
}

fn tenant_shard_score(tenant_id: &str, shard: &TenantShard) -> u128 {
    let hash = sha256_hex(format!("tenant-shard-v1:{tenant_id}:{}", shard.id));
    let score = u128::from_str_radix(&hash[..24], 16).unwrap_or(0);
    score.saturating_mul(shard.weight as u128)
}

pub fn elect_leader(
    nodes: &[ClusterNode],
    current_lease: Option<&LeaderLease>,
    now_epoch: u64,
    lease_ttl_seconds: u64,
) -> QidResult<Option<LeaderLease>> {
    if lease_ttl_seconds == 0 {
        return Err(bad_request("Leader lease TTL must be greater than zero"));
    }
    if let Some(lease) = current_lease
        && lease.expires_at_epoch > now_epoch
        && nodes.iter().any(|node| node.id == lease.leader_id)
    {
        return Ok(Some(lease.clone()));
    }

    let Some(candidate) = nodes
        .iter()
        .filter(|node| now_epoch.saturating_sub(node.last_seen_epoch) <= lease_ttl_seconds)
        .min_by(|a, b| a.priority.cmp(&b.priority).then_with(|| a.id.cmp(&b.id)))
    else {
        return Ok(None);
    };

    Ok(Some(LeaderLease {
        leader_id: candidate.id.clone(),
        term: current_lease.map(|lease| lease.term + 1).unwrap_or(1),
        expires_at_epoch: now_epoch + lease_ttl_seconds,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leader_election_preserves_live_lease_and_elects_priority_candidate() {
        let nodes = vec![
            ClusterNode {
                id: "node-b".to_string(),
                region: "us-east-1".to_string(),
                priority: 20,
                last_seen_epoch: 100,
            },
            ClusterNode {
                id: "node-a".to_string(),
                region: "us-east-1".to_string(),
                priority: 10,
                last_seen_epoch: 100,
            },
        ];
        let lease = elect_leader(&nodes, None, 100, 30).unwrap().unwrap();

        assert_eq!(lease.leader_id, "node-a");
        assert_eq!(lease.term, 1);

        let preserved = elect_leader(&nodes, Some(&lease), 110, 30)
            .unwrap()
            .unwrap();
        assert_eq!(preserved, lease);
    }

    #[test]
    fn tenant_sharding_assigns_deterministic_primary_and_replicas() {
        let shards = vec![
            TenantShard {
                id: "shard-a".to_string(),
                region: "us-east-1".to_string(),
                weight: 100,
                writable: true,
            },
            TenantShard {
                id: "shard-b".to_string(),
                region: "us-west-2".to_string(),
                weight: 100,
                writable: true,
            },
            TenantShard {
                id: "shard-c".to_string(),
                region: "eu-west-1".to_string(),
                weight: 50,
                writable: false,
            },
        ];

        let first = plan_tenant_shard("tenant-alpha", &shards, None, 2);
        let second = plan_tenant_shard("tenant-alpha", &shards, None, 2);

        assert_eq!(first, second);
        assert_eq!(first.status, TenantShardPlanStatus::Ready);
        assert!(first.primary_shard_id.is_some());
        assert_eq!(first.replica_shard_ids.len(), 2);
        assert!(
            !first
                .replica_shard_ids
                .contains(first.primary_shard_id.as_ref().unwrap())
        );
        assert_eq!(
            first.routing_key,
            Some(format!(
                "tenant:tenant-alpha:shard:{}",
                first.primary_shard_id.as_ref().unwrap()
            ))
        );
    }

    #[test]
    fn tenant_sharding_honors_preferred_region_and_rejects_invalid_topology() {
        let shards = vec![
            TenantShard {
                id: "east-a".to_string(),
                region: "us-east-1".to_string(),
                weight: 100,
                writable: true,
            },
            TenantShard {
                id: "west-a".to_string(),
                region: "us-west-2".to_string(),
                weight: 100,
                writable: true,
            },
        ];
        let plan = plan_tenant_shard("tenant-beta", &shards, Some("us-west-2"), 1);

        assert_eq!(plan.status, TenantShardPlanStatus::Ready);
        assert_eq!(plan.primary_region.as_deref(), Some("us-west-2"));
        assert_eq!(plan.primary_shard_id.as_deref(), Some("west-a"));

        let rejected = plan_tenant_shard("tenant-beta", &shards, Some("ap-northeast-1"), 1);
        assert_eq!(rejected.status, TenantShardPlanStatus::Rejected);
        assert!(
            rejected
                .reasons
                .contains(&"no_writable_shard_in_preferred_region:ap-northeast-1".to_string())
        );

        let invalid = plan_tenant_shard(
            "",
            &[TenantShard {
                id: "bad".to_string(),
                region: "us-east-1".to_string(),
                weight: 0,
                writable: true,
            }],
            None,
            0,
        );
        assert_eq!(invalid.status, TenantShardPlanStatus::Rejected);
        assert!(invalid.reasons.contains(&"empty_tenant_id".to_string()));
        assert!(
            invalid
                .reasons
                .contains(&"shard_weight_zero:bad".to_string())
        );
    }

    #[test]
    fn active_active_topology_requires_writable_cross_region_replicas() {
        let shards = vec![
            TenantShard {
                id: "east-a".to_string(),
                region: "us-east-1".to_string(),
                weight: 100,
                writable: true,
            },
            TenantShard {
                id: "west-a".to_string(),
                region: "us-west-2".to_string(),
                weight: 100,
                writable: true,
            },
            TenantShard {
                id: "eu-a".to_string(),
                region: "eu-west-1".to_string(),
                weight: 100,
                writable: true,
            },
        ];

        let plan = plan_active_active_topology(&shards, 3, 2);

        assert_eq!(plan.status, ActiveActiveTopologyStatus::Ready);
        assert_eq!(plan.region_count, 3);
        assert_eq!(plan.writable_region_count, 3);
        assert_eq!(plan.required_replica_count, 2);
        assert!(plan.reasons.is_empty());
    }

    #[test]
    fn active_active_topology_rejects_single_region_and_read_only_writers() {
        let single_region = vec![
            TenantShard {
                id: "east-a".to_string(),
                region: "us-east-1".to_string(),
                weight: 100,
                writable: true,
            },
            TenantShard {
                id: "east-b".to_string(),
                region: "us-east-1".to_string(),
                weight: 100,
                writable: false,
            },
        ];

        let rejected = plan_active_active_topology(&single_region, 2, 1);

        assert_eq!(rejected.status, ActiveActiveTopologyStatus::Rejected);
        assert!(
            rejected
                .reasons
                .contains(&"insufficient_regions:1/2".to_string())
        );
        assert!(
            rejected
                .reasons
                .contains(&"insufficient_writable_regions:1/2".to_string())
        );
        assert!(
            rejected
                .reasons
                .contains(&"cross_region_replica_unavailable".to_string())
        );

        let no_writer = vec![
            TenantShard {
                id: "east-a".to_string(),
                region: "us-east-1".to_string(),
                weight: 100,
                writable: false,
            },
            TenantShard {
                id: "west-a".to_string(),
                region: "us-west-2".to_string(),
                weight: 100,
                writable: false,
            },
        ];
        let rejected = plan_active_active_topology(&no_writer, 2, 1);

        assert_eq!(rejected.status, ActiveActiveTopologyStatus::Rejected);
        assert!(
            rejected
                .reasons
                .contains(&"insufficient_writable_regions:0/2".to_string())
        );
        assert!(rejected.reasons.contains(&"no_writable_shard".to_string()));
    }
}
