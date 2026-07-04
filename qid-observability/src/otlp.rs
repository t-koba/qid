#[cfg(feature = "otel-otlp")]
pub mod otlp_impl {
    use crate::log::OtlpGuard;
    use qid_core::error::{QidError, QidResult};

    pub fn init_otlp_tracing(endpoint: &str) -> QidResult<OtlpGuard> {
        if endpoint.trim().is_empty() {
            return Err(QidError::Config {
                message: "OTLP endpoint must not be empty".to_string(),
            });
        }
        Ok(crate::log::init_otlp_tracing(endpoint))
    }
}

#[cfg(not(feature = "otel-otlp"))]
pub mod otlp_impl {
    use qid_core::error::{QidError, QidResult};

    pub fn init_otlp_tracing(_endpoint: &str) -> QidResult<()> {
        Err(QidError::Config {
            message: "OTLP tracing requires the otel-otlp feature".to_string(),
        })
    }
}

pub use otlp_impl::init_otlp_tracing;
