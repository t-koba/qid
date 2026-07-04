use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

/// Initialize structured logging.
pub fn init_logging(json: bool) {
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));

    if json {
        tracing_subscriber::registry()
            .with(tracing_subscriber::fmt::layer().json())
            .with(env_filter)
            .init();
    } else {
        tracing_subscriber::registry()
            .with(tracing_subscriber::fmt::layer())
            .with(env_filter)
            .init();
    }
}

/// Initialize OTLP trace exporter and return a shutdown guard.
///
/// Requires the `otel-otlp` feature.
#[cfg(feature = "otel-otlp")]
pub fn init_otlp_tracing(endpoint: &str) -> OtlpGuard {
    use opentelemetry::{KeyValue, global};
    use opentelemetry_otlp::WithExportConfig;
    use opentelemetry_sdk::Resource;
    use opentelemetry_sdk::trace::TracerProvider;

    let exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_tonic()
        .with_endpoint(endpoint)
        .build()
        .expect("failed to create OTLP span exporter");

    let provider = TracerProvider::builder()
        .with_batch_exporter(exporter, opentelemetry_sdk::runtime::Tokio)
        .with_resource(Resource::new(vec![KeyValue::new("service.name", "qid")]))
        .build();

    let _ = global::set_tracer_provider(provider.clone());

    OtlpGuard { provider }
}

/// Guard that shuts down the OTLP tracer provider on drop.
#[cfg(feature = "otel-otlp")]
pub struct OtlpGuard {
    provider: opentelemetry_sdk::trace::TracerProvider,
}

#[cfg(feature = "otel-otlp")]
impl Drop for OtlpGuard {
    fn drop(&mut self) {
        if let Err(e) = self.provider.shutdown() {
            tracing::warn!("OTLP tracer provider shutdown error: {e}");
        }
    }
}
