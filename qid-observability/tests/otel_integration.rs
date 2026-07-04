#[test]
fn init_otlp_tracing_function_exists() {
    // Verify the function is importable and has the expected signature.
    // A full integration test requires an OTLP collector.
    fn _type_check() {
        let _guard: qid_observability::OtlpGuard =
            qid_observability::init_otlp_tracing("http://localhost:4317");
    }
}
