//! Observability for qid: logs, metrics, audit events.
#![forbid(unsafe_code)]

pub mod audit;
pub mod log;
pub mod metrics;
pub mod openmetrics;
#[cfg(feature = "otel-otlp")]
mod otlp;
pub mod syslog;

pub use log::init_logging;
