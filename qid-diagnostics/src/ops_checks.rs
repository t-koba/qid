use super::*;

pub(crate) fn check_ops_cache(config: &QidConfig) -> Vec<CheckItem> {
    let mut checks = Vec::new();
    let cache = &config.ops.cache;
    let name = "ops.cache";
    match cache.kind.as_str() {
        "disabled" => checks.push(check_ok(name, "cache is disabled")),
        "redis" | "valkey" => {
            let mut ok = true;
            if cache.endpoints.is_empty() {
                checks.push(check_error(
                    name,
                    "redis/valkey cache requires at least one endpoint",
                ));
                ok = false;
            }
            if cache.key_prefix.is_empty() {
                checks.push(check_error(name, "redis/valkey cache requires key_prefix"));
                ok = false;
            }
            if cache.ttl_seconds == 0 {
                checks.push(check_error(
                    name,
                    "redis/valkey cache requires ttl_seconds > 0",
                ));
                ok = false;
            }
            if ok {
                checks.push(check_ok(name, "redis/valkey cache configured"));
            }
        }
        other => checks.push(check_warning(name, format!("unknown cache kind: {other}"))),
    }
    checks
}

pub(crate) fn check_ops_cluster(config: &QidConfig) -> Vec<CheckItem> {
    let mut checks = Vec::new();
    let cluster = &config.ops.cluster;
    let name = "ops.cluster";
    if cluster.leader_lease_ttl_seconds == 0 {
        checks.push(check_warning(
            name,
            "leader_lease_ttl_seconds is 0 (leader election disabled)",
        ));
    } else {
        checks.push(check_ok(name, "leader_lease_ttl_seconds configured"));
    }
    if cluster.multi_region_active_active {
        if cluster.cluster_id.is_some() && cluster.region.is_some() && cluster.node_id.is_some() {
            checks.push(check_ok(
                name,
                "multi-region active-active fully configured",
            ));
        } else {
            checks.push(check_warning(name, "multi-region active-active enabled but cluster_id/region/node_id partially configured"));
        }
    }
    checks
}

pub(crate) fn check_ops_backup(config: &QidConfig) -> Vec<CheckItem> {
    let mut checks = Vec::new();
    let backup = &config.ops.backup;
    let name = "ops.backup";
    if backup.enabled {
        if backup.object_store_uri.is_none() {
            checks.push(check_error(
                name,
                "backup enabled but object_store_uri not set",
            ));
        } else {
            checks.push(check_ok(name, "backup configured with object store URI"));
        }
        if backup.migration_version.is_none() {
            checks.push(check_warning(
                name,
                "backup enabled but migration_version not set",
            ));
        }
    } else {
        checks.push(check_ok(name, "backup is disabled"));
    }
    checks
}
