use super::*;

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("qid-source-size-{}-{unique}", std::process::id()));
        fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn write(&self, path: &str, content: impl AsRef<[u8]>) {
        let path = self.0.join(path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, content).unwrap();
    }

    fn package(&self, name: &str) -> (String, PathBuf) {
        (name.to_string(), self.0.join(name).join("Cargo.toml"))
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

#[test]
fn source_size_command_and_baseline_use_the_report() {
    assert!(matches!(
        Args::try_parse_from(["xtask", "source-size"])
            .unwrap()
            .command,
        Command::SourceSize
    ));
    assert!(Args::try_parse_from(["xtask", "budget"]).is_err());
    let plan = gate_plan(GateSuite::Baseline);
    let report = plan.iter().find(|item| item.name == "source-size").unwrap();
    assert_eq!(report.display(), "cargo run -p xtask -- source-size");
}

#[test]
fn source_size_reports_large_measurements_without_thresholds() {
    let fixture = Fixture::new();
    // Exceed the retired per-crate and total caps; neither can reject a report.
    fixture.write("large/src/lib.rs", "// source\n".repeat(120_000));
    fixture.write("large/src/inline.rs", "#[cfg(test)]\nmod tests {}\n\n");
    fixture.write("large/tests/integration.rs", "// test\n\n");
    fixture.write("large/src/unit_tests.rs", "// standalone test\n");
    fixture.write("large/target/ignored.rs", "// ignored\n");
    fixture.write("large/README.md", "ignored\n");
    fixture.write("support-tests/src/lib.rs", "// test package\n");
    let packages = [fixture.package("large"), fixture.package("support-tests")];
    let mut output = Vec::new();
    write_source_size_report(&packages, &mut output).unwrap();
    let report = String::from_utf8(output).unwrap();
    assert_eq!(
        report,
        format!(
            "Rust source-size measurements (report only):\n{:-<88}\n  {:30} {:>6} source lines; {:>6} test lines\n  {:30} {:>6} source lines; {:>6} test lines\n{:-<88}\n  {:30} {:>6} source lines; {:>6} test lines\n",
            "", "large", 120_003, 3, "support-tests", 0, 1, "", "Total", 120_003, 4
        )
    );
}

#[test]
fn source_size_propagates_measurement_and_output_errors() {
    let fixture = Fixture::new();
    let packages = [fixture.package("missing")];
    assert!(write_source_size_report(&packages, &mut Vec::new()).is_err());
    fixture.write("missing/src/lib.rs", [0xff]);
    assert!(write_source_size_report(&packages, &mut Vec::new()).is_err());
    fixture.write("missing/src/lib.rs", "// readable\n");
    assert!(write_source_size_report(&packages, &mut Vec::new()).is_ok());
    assert!(write_source_size_report(&packages, &mut io::Cursor::new(&mut [][..])).is_err());
}

#[test]
fn source_size_classifies_test_paths_and_standalone_test_files() {
    for path in [
        "tests/property.rs",
        "src/test.rs",
        "src/config/tests.rs",
        "src/test_config.rs",
        "src/config_test.rs",
        "src/property_tests.rs",
    ] {
        assert!(is_test_rs_file("qid-core", Path::new(path)), "{path}");
    }
    for path in [
        "src/foo_test_bar.rs",
        "src/my_test_helper.rs",
        "src/config.rs",
    ] {
        assert!(!is_test_rs_file("qid-core", Path::new(path)), "{path}");
    }
    assert!(is_test_rs_file(
        "qid-oauth-token-tests",
        Path::new("src/lib.rs")
    ));
}
