use qid_core::config::ObservabilityConfig;
use tracing_subscriber::{Layer, layer::SubscriberExt, util::SubscriberInitExt};

/// Owns the optional exporter until the daemon stops. Shut down while Tokio is alive.
pub struct LoggingGuard {
    #[cfg(feature = "otel-otlp")]
    provider: Option<opentelemetry_sdk::trace::SdkTracerProvider>,
}

impl LoggingGuard {
    /// Flush completed spans and shut down off the async runtime thread, including
    /// on a current-thread runtime. Export failures never expose collector details.
    pub async fn shutdown(self) -> anyhow::Result<()> {
        #[cfg(feature = "otel-otlp")]
        if let Some(provider) = self.provider {
            return tokio::task::spawn_blocking(move || {
                let flushed = provider.force_flush();
                let stopped = provider.shutdown();
                flushed
                    .and(stopped)
                    .map_err(|_| anyhow::anyhow!("OTLP flush/shutdown failed"))
            })
            .await
            .map_err(|_| anyhow::anyhow!("OTLP shutdown task failed"))?;
        }
        Ok(())
    }
}

/// Install one subscriber for configured logs and optional OTLP spans. RUST_LOG
/// filters both; without a valid RUST_LOG, the default remains `info`.
/// Call on a Tokio runtime. For HTTPS, the host selects a process-wide rustls
/// crypto provider when multiple backends are enabled (as qidd does).
pub async fn init_logging(config: &ObservabilityConfig) -> anyhow::Result<LoggingGuard> {
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    let (subscriber, guard) = build_subscriber(config, env_filter, std::io::stdout)?;
    if subscriber.try_init().is_err() {
        guard.shutdown().await?;
        anyhow::bail!("failed to install observability subscriber");
    }
    Ok(guard)
}

// Shared by the global initializer and scoped tests, so tests exercise exactly
// the subscriber composition the daemon installs, without global test conflicts.
fn build_subscriber(
    config: &ObservabilityConfig,
    env_filter: tracing_subscriber::EnvFilter,
    writer: impl for<'a> tracing_subscriber::fmt::MakeWriter<'a> + Send + Sync + 'static,
) -> anyhow::Result<(impl tracing::Subscriber + Send + Sync, LoggingGuard)> {
    config.tracing.validate()?;
    let format = if config.logs.json() {
        tracing_subscriber::fmt::layer()
            .with_writer(writer)
            .json()
            .boxed()
    } else {
        tracing_subscriber::fmt::layer().with_writer(writer).boxed()
    };
    let subscriber = tracing_subscriber::registry().with(format).with(env_filter);
    #[cfg(feature = "otel-otlp")]
    {
        use opentelemetry::trace::TracerProvider;
        let provider = crate::otlp::build_provider(&config.tracing)?;
        let layer = provider.as_ref().map(|provider| {
            tracing_opentelemetry::layer()
                .with_tracer(provider.tracer("qidd"))
                .with_error_fields_to_exceptions(false)
                .with_error_records_to_exceptions(false)
                .with_filter(tracing_subscriber::filter::filter_fn(|meta| meta.is_span()))
        });
        Ok((subscriber.with(layer), LoggingGuard { provider }))
    }
    #[cfg(not(feature = "otel-otlp"))]
    {
        if config.tracing.endpoint.is_some() {
            anyhow::bail!("observability.tracing.endpoint requires the otel-otlp build feature");
        }
        Ok((subscriber, LoggingGuard {}))
    }
}

#[cfg(test)]
#[path = "log_tests.rs"]
mod tests;
