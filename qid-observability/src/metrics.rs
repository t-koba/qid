use metrics_exporter_prometheus::PrometheusBuilder;
use std::net::SocketAddr;

/// Start the Prometheus metrics exporter.
pub fn init_metrics(listen: &str) -> anyhow::Result<()> {
    let addr: SocketAddr = listen.parse()?;
    PrometheusBuilder::new()
        .with_http_listener(addr)
        .install()?;
    Ok(())
}
