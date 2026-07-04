//! Policy engine for qid with Native, Cedar, and Rego adapters.
#![forbid(unsafe_code)]

pub mod cedar;
#[cfg(feature = "cedar-embedded")]
pub mod cedar_embedded;
pub mod models;
pub mod native;
pub mod rego;

pub use cedar::CedarPolicyEngine;
#[cfg(feature = "cedar-embedded")]
pub use cedar_embedded::CedarEmbeddedPolicyEngine;
pub use models::{
    Condition, Decision, DecisionDetails, Expression, PepPolicyActions, PolicyBundle,
    PolicyContext, PolicyEngine, RebacEvaluator,
};
pub use native::NativePolicyEngine;
pub use rego::RegoPolicyEngine;

/// Create a policy engine by kind string ("native", "cedar", "rego", "cedar-embedded").
pub fn create_policy_engine(kind: &str) -> Box<dyn PolicyEngine> {
    match kind {
        "cedar" => Box::new(CedarPolicyEngine::default()),
        "rego" => Box::new(RegoPolicyEngine::default()),
        #[cfg(feature = "cedar-embedded")]
        "cedar-embedded" => Box::new(CedarEmbeddedPolicyEngine::empty()),
        _ => Box::new(NativePolicyEngine::new()),
    }
}
