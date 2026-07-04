//! Trusted Types (CSP v3 DOM XSS defense).

pub fn trusted_types_policy(allowed: &[&str]) -> String {
    let policies = allowed.join(" ");
    format!("trusted-types {policies}; require-trusted-types-for 'script'")
}

pub fn default_trusted_types_policy() -> String {
    trusted_types_policy(&["qid-ui", "qid-template"])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_policy() {
        let policy = trusted_types_policy(&["policy-1"]);
        assert!(policy.contains("trusted-types policy-1"));
        assert!(policy.contains("require-trusted-types-for 'script'"));
    }

    #[test]
    fn default_policy() {
        let policy = default_trusted_types_policy();
        assert!(policy.contains("qid-ui"));
    }
}
