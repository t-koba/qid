use anyhow::anyhow;
use opentelemetry::KeyValue;
use opentelemetry_otlp::WithTonicConfig;
use opentelemetry_sdk::{
    Resource,
    runtime::Tokio,
    trace::{
        BatchConfigBuilder, Sampler, SdkTracerProvider,
        span_processor_with_async_runtime::BatchSpanProcessor,
    },
};
use qid_core::config::TracingConfig;
use std::time::Duration;
use tonic::transport::{Channel, ClientTlsConfig};

pub(crate) fn build_provider(config: &TracingConfig) -> anyhow::Result<Option<SdkTracerProvider>> {
    let Some(endpoint) = &config.endpoint else {
        return Ok(None);
    };
    tokio::runtime::Handle::try_current()
        .map_err(|_| anyhow!("OTLP initialization requires a Tokio runtime"))?;
    let timeout = Duration::from_millis(config.export_timeout_ms);
    // A custom channel prevents OTEL_EXPORTER_OTLP_* environment variables from
    // overriding the validated endpoint or the configured transport timeout.
    let mut channel = Channel::from_shared(endpoint.clone())
        .map_err(|_| anyhow!("invalid OTLP endpoint"))?
        .timeout(timeout)
        .connect_timeout(timeout);
    if endpoint
        .split(':')
        .next()
        .is_some_and(|scheme| scheme.eq_ignore_ascii_case("https"))
    {
        channel = channel
            .tls_config(ClientTlsConfig::new().with_native_roots())
            .map_err(|_| anyhow!("failed to configure OTLP TLS"))?;
    }
    let exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_tonic()
        .with_channel(channel.connect_lazy())
        .build()
        .map_err(|_| anyhow!("failed to build OTLP span exporter"))?;
    let batch = BatchConfigBuilder::default()
        .with_max_queue_size(config.max_queue_size)
        .with_max_export_batch_size(config.max_export_batch_size)
        .with_scheduled_delay(Duration::from_millis(config.scheduled_delay_ms))
        .with_max_export_timeout(timeout)
        .with_max_concurrent_exports(1)
        .build();
    let processor = BatchSpanProcessor::builder(exporter, Tokio)
        .with_batch_config(batch)
        .build();
    Ok(Some(
        SdkTracerProvider::builder()
            .with_span_processor(processor)
            .with_sampler(Sampler::ParentBased(Box::new(Sampler::AlwaysOn)))
            .with_resource(
                Resource::builder_empty()
                    .with_attribute(KeyValue::new("service.name", config.service_name.clone()))
                    .build(),
            )
            .build(),
    ))
}
