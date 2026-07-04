//! Observability for qid: logs, metrics, audit events.
#![forbid(unsafe_code)]

pub mod audit;
pub mod log;
pub mod metrics;
pub mod openmetrics;
pub mod otlp;
pub mod syslog;

pub use log::init_logging;

#[cfg(feature = "otel-otlp")]
pub use log::{OtlpGuard, init_otlp_tracing};
