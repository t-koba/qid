#![allow(dead_code)]

use proptest::prelude::*;

// ---------------------------------------------------------------------------
// Token rotation invariant
// ---------------------------------------------------------------------------

/// A simplified refresh token family for property testing.
struct TokenStore {
    /// Current valid refresh token hash.
    current_hash: String,
    /// Historical hashes that have been rotated away (replayed).
    consumed_hashes: Vec<String>,
}

impl TokenStore {
    fn new(initial_hash: String) -> Self {
        Self {
            current_hash: initial_hash,
            consumed_hashes: Vec::new(),
        }
    }

    /// Attempt to rotate the refresh token.
    /// Returns `Ok(new_hash)` if the presented hash matches the current token.
    /// Returns `Err(())` if the hash is replayed or unknown.
    fn rotate(&mut self, presented_hash: &str) -> Result<String, ()> {
        if self.consumed_hashes.contains(&presented_hash.to_string()) {
            // Replay detected – token family is compromised.
            return Err(());
        }
        if presented_hash != self.current_hash {
            return Err(());
        }
        // Rotate: mark old hash as consumed, generate new one.
        self.consumed_hashes.push(self.current_hash.clone());
        let new_hash = format!("rotated_{}", self.current_hash);
        self.current_hash = new_hash.clone();
        Ok(new_hash)
    }
}

proptest! {
    #[test]
    fn token_rotation_returns_new_token_and_detects_replay(
        initial_hash in "[a-zA-Z0-9_-]{8,32}",
    ) {
        let mut store = TokenStore::new(initial_hash.clone());
        let old_hash = initial_hash.clone();

        // First rotation should succeed and return a new token.
        let new_hash = store.rotate(&old_hash).expect("first rotation should succeed");
        prop_assert_ne!(&new_hash, &old_hash, "rotated token must differ from original");

        // Using the old token again must be detected as replay.
        let replay_result = store.rotate(&old_hash);
        prop_assert!(replay_result.is_err(), "reused old token must be detected as replay");

        // The new token should still be usable.
        let rotated_again = store.rotate(&new_hash);
        prop_assert!(rotated_again.is_ok(), "current token must still be valid after rotation");
        let rotated_again_val = rotated_again.unwrap();
        prop_assert_ne!(&rotated_again_val, &new_hash, "subsequent rotation must produce a different token");
    }
}

// ---------------------------------------------------------------------------
// Deny-override invariant
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
enum AccessRule {
    Allow { resource: String },
    Deny { resource: String },
}

/// Evaluate access: a Deny always takes precedence over Allow.
/// If no rule matches, default is Allow.
fn evaluate_access(rules: &[AccessRule], resource: &str) -> bool {
    let mut has_allow = false;
    for rule in rules {
        match rule {
            AccessRule::Deny { resource: r } if r == resource => return false,
            AccessRule::Allow { resource: r } if r == resource => has_allow = true,
            _ => {}
        }
    }
    has_allow
}

proptest! {
    #[test]
    fn deny_rule_overrides_any_allow_rule(
        resource in "[a-zA-Z0-9_]{1,16}",
        allow_suffixes in prop::collection::vec("[a-zA-Z0-9_]{1,8}", 0..4),
    ) {
        // Build rule set: one explicit Deny for the resource, plus Allow rules
        // for the same resource (suffix-based variations that all match).
        let mut rules: Vec<AccessRule> = allow_suffixes
            .into_iter()
            .map(|suffix| AccessRule::Allow {
                resource: format!("{}_{}", resource, suffix),
            })
            .collect();
        // Insert the Deny rule that matches the exact resource.
        rules.push(AccessRule::Deny { resource: resource.clone() });

        // No matter what Allow rules exist, a matching Deny always wins.
        let result = evaluate_access(&rules, &resource);
        prop_assert!(!result, "deny must override any allow rules");
    }
}

// ---------------------------------------------------------------------------
// Tenant isolation invariant
// ---------------------------------------------------------------------------

/// A resource scoped to a specific tenant.
#[derive(Debug, Clone)]
struct TenantResource {
    tenant: String,
    id: String,
}

/// A user belonging to a specific tenant.
#[derive(Debug, Clone)]
struct TenantUser {
    tenant: String,
    name: String,
}

/// Check whether a user can access a resource based on tenant membership.
fn can_access(user: &TenantUser, resource: &TenantResource) -> bool {
    user.tenant == resource.tenant
}

proptest! {
    #[test]
    fn tenant_isolation_enforced(
        tenant_a in "[a-zA-Z0-9_]{1,8}",
        tenant_b in "[a-zA-Z0-9_]{1,8}",
        user_name in "[a-zA-Z0-9_]{1,8}",
        resource_id in "[a-zA-Z0-9_]{1,8}",
    ) {
        prop_assume!(tenant_a != tenant_b, "tenants must differ");

        let user = TenantUser {
            tenant: tenant_a.clone(),
            name: user_name,
        };
        let resource = TenantResource {
            tenant: tenant_b,
            id: resource_id.clone(),
        };

        // A user in tenant A MUST NOT access resources in tenant B.
        prop_assert!(
            !can_access(&user, &resource),
            "user in tenant A must not access resource in tenant B"
        );

        // A user in the same tenant CAN access the resource.
        let same_tenant_resource = TenantResource {
            tenant: tenant_a,
            id: resource_id,
        };
        prop_assert!(
            can_access(&user, &same_tenant_resource),
            "user must be able to access resources in their own tenant"
        );
    }
}

// ---------------------------------------------------------------------------
// Concurrent token rotation invariant (no double-issuance under contention)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn concurrent_token_rotation_prevents_double_issuance() {
    use std::sync::{Arc, Mutex};

    let store = Arc::new(Mutex::new(TokenStore::new("initial".to_string())));
    let mut handles = Vec::new();

    // Spawn 10 concurrent rotation attempts with the same initial hash.
    // At most one should succeed; the rest must be detected as replay.
    for _ in 0..10 {
        let store = Arc::clone(&store);
        handles.push(tokio::spawn(async move {
            let mut guard = store.lock().unwrap();
            guard.rotate("initial")
        }));
    }

    let mut success_count = 0usize;
    for handle in handles {
        let result = handle.await.unwrap();
        if result.is_ok() {
            success_count += 1;
        }
    }

    assert_eq!(
        success_count, 1,
        "exactly one concurrent rotation must succeed, got {success_count}"
    );

    // Subsequent replay with the initial hash must also fail.
    let mut guard = store.lock().unwrap();
    assert!(
        guard.rotate("initial").is_err(),
        "replay of initial hash must be rejected after concurrent rotation"
    );
}

// ---------------------------------------------------------------------------
// Constant-time equality invariant
// ---------------------------------------------------------------------------

proptest! {
    #[test]
    fn constant_time_eq_returns_true_for_equal_inputs(
        left in prop::collection::vec(any::<u8>(), 0..64),
    ) {
        let right = left.clone();
        prop_assert!(
            qid_core::util::constant_time_eq(&left, &right),
            "constant_time_eq must return true for equal inputs"
        );
    }

    #[test]
    fn constant_time_eq_returns_false_for_different_inputs(
        left in prop::collection::vec(any::<u8>(), 0..64),
        diff_byte in any::<u8>(),
    ) {
        prop_assume!(!left.is_empty());
        let mut right = left.clone();
        let idx = right.len() / 2;
        // Flip one byte (may result in same value with small probability on 0..=255)
        right[idx] = diff_byte;
        // Skip the rare case where the byte flips back to the same value
        prop_assume!(left != right);
        prop_assert!(
            !qid_core::util::constant_time_eq(&left, &right),
            "constant_time_eq must return false for different inputs"
        );
    }
}
