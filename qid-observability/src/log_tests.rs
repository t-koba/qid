use super::*;

fn subscriber(
    config: &ObservabilityConfig,
) -> anyhow::Result<(impl tracing::Subscriber + Send + Sync, LoggingGuard)> {
    build_subscriber(
        config,
        tracing_subscriber::EnvFilter::new("info"),
        std::io::sink,
    )
}

#[tokio::test]
async fn unconfigured_export_is_disabled() {
    let config = ObservabilityConfig::default();
    let (subscriber, guard) = subscriber(&config).unwrap();
    tracing::subscriber::with_default(subscriber, || tracing::info!("logs still work"));
    #[cfg(feature = "otel-otlp")]
    assert!(guard.provider.is_none());
    guard.shutdown().await.unwrap();
}

#[test]
fn invalid_endpoint_is_rejected_without_disclosure() {
    let mut config = ObservabilityConfig::default();
    config.tracing.endpoint = Some("https://user:private-value@localhost?private-value".into());
    let error = subscriber(&config).err().unwrap().to_string();
    assert!(error.contains("observability.tracing"));
    assert!(!error.contains("private-value"));
}

#[cfg(not(feature = "otel-otlp"))]
#[test]
fn configured_export_requires_feature() {
    let mut config = ObservabilityConfig::default();
    config.tracing.endpoint = Some("http://localhost:4317".into());
    assert!(
        subscriber(&config)
            .err()
            .unwrap()
            .to_string()
            .contains("otel-otlp")
    );
}

#[cfg(feature = "otel-otlp")]
#[test]
fn configured_export_requires_tokio_runtime() {
    let mut config = ObservabilityConfig::default();
    config.tracing.endpoint = Some("http://localhost:4317".into());
    assert!(
        subscriber(&config)
            .err()
            .unwrap()
            .to_string()
            .contains("Tokio runtime")
    );
}

#[cfg(feature = "otel-otlp")]
mod otlp {
    use super::*;
    use opentelemetry_proto::tonic::{
        collector::trace::v1::{
            ExportTraceServiceRequest, ExportTraceServiceResponse,
            trace_service_server::{TraceService, TraceServiceServer},
        },
        common::v1::any_value::Value,
    };
    use std::{
        io::Write,
        sync::{Arc, Mutex},
        time::Duration,
    };
    use tokio::{
        net::TcpListener,
        sync::{mpsc, oneshot},
    };
    use tokio_stream::wrappers::TcpListenerStream;
    use tonic::{Request, Response, Status};

    #[derive(Clone, Copy)]
    enum CollectorMode {
        Accept,
        Stall,
        Reject,
    }

    struct Collector {
        requests: mpsc::Sender<ExportTraceServiceRequest>,
        mode: CollectorMode,
    }

    #[tonic::async_trait]
    impl TraceService for Collector {
        async fn export(
            &self,
            request: Request<ExportTraceServiceRequest>,
        ) -> Result<Response<ExportTraceServiceResponse>, Status> {
            self.requests.try_send(request.into_inner()).unwrap();
            match self.mode {
                CollectorMode::Accept => {}
                CollectorMode::Stall => std::future::pending::<()>().await,
                CollectorMode::Reject => {
                    return Err(Status::unavailable("private-collector-detail"));
                }
            }
            Ok(Response::new(ExportTraceServiceResponse {
                partial_success: None,
            }))
        }
    }

    #[derive(Clone)]
    struct LogBuffer(Arc<Mutex<Vec<u8>>>);
    impl Write for LogBuffer {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    async fn collector(
        mode: CollectorMode,
    ) -> (
        String,
        mpsc::Receiver<ExportTraceServiceRequest>,
        oneshot::Sender<()>,
        tokio::task::JoinHandle<()>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let (requests, receiver) = mpsc::channel(8);
        let (stop, stopped) = oneshot::channel();
        let task = tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(TraceServiceServer::new(Collector { requests, mode }))
                .serve_with_incoming_shutdown(TcpListenerStream::new(listener), async {
                    let _ = stopped.await;
                })
                .await
                .unwrap();
        });
        (endpoint, receiver, stop, task)
    }

    // Default Tokio tests use a current-thread runtime: blocking SDK shutdown
    // here would deadlock. No process-global subscriber or environment mutation.
    #[tokio::test]
    async fn composed_subscriber_exports_linked_spans_and_flushes_without_log_events() {
        let (endpoint, mut requests, stop, task) = collector(CollectorMode::Accept).await;
        for format in ["json", "text"] {
            let mut config = ObservabilityConfig::default();
            config.logs.format = format.into();
            config.tracing.endpoint = Some(endpoint.clone());
            config.tracing.service_name = "qid-collector-test".into();
            config.tracing.scheduled_delay_ms = 3_600_000;
            let buffer = LogBuffer(Arc::new(Mutex::new(Vec::new())));
            let writer = buffer.clone();
            let (subscriber, guard) = build_subscriber(
                &config,
                tracing_subscriber::EnvFilter::new("info"),
                move || writer.clone(),
            )
            .unwrap();
            tracing::subscriber::with_default(subscriber, || {
                let parent = tracing::info_span!("http_request", method = "GET", route = "/health");
                let _parent = parent.enter();
                tracing::info!(payload = "private-event-body", "sensitive log message");
                let child = tracing::info_span!("decision");
                let _child = child.enter();
                tracing::error!(error = "private-error-detail", "failure log");
                let _filtered = tracing::debug_span!("filtered-out").entered();
            });
            assert!(
                requests.try_recv().is_err(),
                "normal batch delay has not elapsed"
            );
            tokio::time::timeout(Duration::from_secs(5), guard.shutdown())
                .await
                .unwrap()
                .unwrap();
            let request = tokio::time::timeout(Duration::from_secs(2), requests.recv())
                .await
                .unwrap()
                .unwrap();
            assert!(!format!("{request:?}").contains("private-"));
            assert_eq!(request.resource_spans.len(), 1);
            let resource = &request.resource_spans[0];
            let attrs = &resource.resource.as_ref().unwrap().attributes;
            assert!(attrs.iter().any(|kv| kv.key == "service.name"
                && kv.value.as_ref().unwrap().value
                    == Some(Value::StringValue("qid-collector-test".into()))));
            let spans: Vec<_> = resource
                .scope_spans
                .iter()
                .flat_map(|scope| &scope.spans)
                .collect();
            assert_eq!(spans.len(), 2);
            let parent = spans.iter().find(|s| s.name == "http_request").unwrap();
            let child = spans.iter().find(|s| s.name == "decision").unwrap();
            assert_eq!(parent.trace_id, child.trace_id);
            assert_eq!(parent.trace_id.len(), 16);
            assert!(parent.trace_id.iter().any(|b| *b != 0));
            assert!(parent.parent_span_id.is_empty());
            assert_eq!(child.parent_span_id, parent.span_id);
            assert!(spans.iter().all(|s| s.events.is_empty()));
            let output = String::from_utf8(buffer.0.lock().unwrap().clone()).unwrap();
            assert!(output.contains("private-event-body"));
            assert!(output.contains("private-error-detail"));
            if format == "json" {
                assert!(
                    output
                        .lines()
                        .all(|line| serde_json::from_str::<serde_json::Value>(line).is_ok())
                );
            } else {
                assert!(output.contains("INFO"));
            }
        }
        stop.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn collector_outage_is_bounded_and_shutdown_error_is_sanitized() {
        for mode in [CollectorMode::Stall, CollectorMode::Reject] {
            let (endpoint, _requests, _stop, task) = collector(mode).await;
            let mut config = ObservabilityConfig::default();
            config.tracing.endpoint = Some(endpoint.clone());
            config.tracing.scheduled_delay_ms = 3_600_000;
            config.tracing.export_timeout_ms = 100;
            let (subscriber, guard) = subscriber(&config).unwrap();
            tracing::subscriber::with_default(subscriber, || {
                let _span = tracing::info_span!("outage").entered();
            });
            let error = tokio::time::timeout(Duration::from_secs(3), guard.shutdown())
                .await
                .unwrap()
                .unwrap_err()
                .to_string();
            assert_eq!(error, "OTLP flush/shutdown failed");
            assert!(!error.contains(&endpoint));
            task.abort();
            assert!(task.await.unwrap_err().is_cancelled());
        }
    }
}
