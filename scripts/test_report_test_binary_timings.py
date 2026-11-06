"""Focused stdlib tests for normal Cargo test-binary timing artifacts."""

import contextlib
import csv
import importlib.util
import io
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

spec = importlib.util.spec_from_file_location(
    "binary_timings", Path(__file__).with_name("report-test-binary-timings.py")
)
timings = importlib.util.module_from_spec(spec)
spec.loader.exec_module(timings)


OK = ("test result: ok. 2 passed; 0 failed; 1 ignored; 0 measured; "
      "0 filtered out; finished in 1.23s\n")
RUN = "     Running unittests src/lib.rs (target/debug/deps/qid_worker-ab12)\n"


class BinaryTimingsTests(unittest.TestCase):
    def test_colored_multiple_binaries_and_doc_tests(self):
        log = (
            "Compiling qid-worker\n"
            "\x1b[1m\x1b[32m     Running\x1b[0m unittests src/lib.rs "
            "(target/debug/deps/qid_worker-ab12)\n"
            "running 3 tests\ntest private_test_name ... ok\n" + OK +
            "     Running unittests src/main.rs (target/debug/deps/qidd-cd34)\n"
            "running 0 tests\n"
            "test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; "
            "0 filtered out; finished in 0.00s\n"
            "   Doc-tests qid_worker\n" + OK + "   Doc-tests qid_core\n" + OK
        )
        self.assertEqual(timings.parse_timings(io.StringIO(log)), [
            ("qid_worker-ab12", "1.23", "ok", "2", "0", "1", "0", "0"),
            ("qidd-cd34", "0.00", "ok", "0", "0", "0", "0", "0"),
        ])

    def test_windows_crlf_failed_binary_csv_has_no_paths_or_test_names(self):
        log = (
            "     Running tests/worker.rs "
            "(D:\\a\\project (copy)\\target\\debug\\deps\\worker-deadbeef.exe)\r\n"
            "test private_test_name ... FAILED\r\n"
            "failures:\r\n    private_test_name\r\n"
            "test result: FAILED. 1 passed; 2 failed; 3 ignored; 4 measured; "
            "5 filtered out; finished in 12.50s\r\n"
            "error: test failed, to rerun pass `-p qid-worker --test worker`\r\n"
        )
        with tempfile.TemporaryDirectory() as directory:
            source, output = Path(directory) / "cargo.log", Path(directory) / "timings.csv"
            source.write_bytes(log.encode("utf-8"))
            self.assertEqual(timings.main(["--input", str(source), "--output", str(output)]), 0)
            with output.open(newline="", encoding="utf-8") as handle:
                self.assertEqual(list(csv.DictReader(handle)), [dict(zip(timings.FIELDS, (
                    "worker-deadbeef.exe", "12.50", "FAILED", "1", "2", "3", "4", "5"
                )))])
            for private in ("D:", "project", "private_test_name", "error:", "tests/worker.rs"):
                self.assertNotIn(private, output.read_text(encoding="utf-8"))

    def test_incomplete_unpaired_and_malformed_input_fails_closed(self):
        for log in (
            "", "Compiling only\n", OK, RUN, RUN + RUN + OK,
            RUN + "   Doc-tests qid_worker\n" + OK,
            RUN + OK.replace("1.23s", "unknown"),
            RUN + OK + OK,
            "Running malformed\n" + OK,
            "Running tests/a.rs (target/debug/deps/=formula)\n" + OK,
            RUN + OK + RUN,  # Do not publish a plausible but partial report.
        ):
            with self.subTest(log=log), self.assertRaises(ValueError):
                timings.parse_timings(io.StringIO(log))

    def test_report_failure_is_visible_and_removes_stale_output(self):
        with tempfile.TemporaryDirectory() as directory:
            source, output = Path(directory) / "cargo.log", Path(directory) / "timings.csv"
            for content in (None, RUN + "test sensitive_name ... "):
                if content is not None:
                    source.write_text(content, encoding="utf-8")
                output.write_text("stale evidence", encoding="utf-8")
                errors = io.StringIO()
                with contextlib.redirect_stderr(errors):
                    self.assertEqual(timings.main([
                        "--input", str(source), "--output", str(output)
                    ]), 1)
                self.assertFalse(output.exists())
                self.assertIn("timing report failed", errors.getvalue())
                self.assertNotIn("sensitive_name", errors.getvalue())
            source.write_text(RUN + OK, encoding="utf-8")
            with contextlib.redirect_stderr(io.StringIO()) as errors:
                self.assertEqual(timings.main([
                    "--input", str(source), "--output", str(output / "missing" / "timings.csv")
                ]), 1)
            self.assertIn("timing report failed", errors.getvalue())

    def test_workflow_capture_reports_same_run_and_preserves_status(self):
        root = Path(__file__).resolve().parents[1]
        workflow = (root / ".github/workflows/test.yml").read_text()
        block = workflow.split("      - name: Test workspace\n", 1)[1].split("      - name:", 1)[0]
        script = "\n".join(line[10:] for line in block.split("        run: |\n", 1)[1].splitlines())
        # Exercise the actual workflow shell without invoking Cargo or running tests.
        fake_cargo = '''cargo() {
          [[ "$*" == 'test --workspace --locked -- --test-threads=1' ]] || return 99
          echo '     Running unittests src/lib.rs (target/debug/deps/qid_worker-ab12)'
          if [[ "$FAKE_STATUS" -eq 0 ]]; then
            echo 'test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1.23s'
          else
            echo 'test result: FAILED. 1 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1.23s'
          fi
          echo standard-output
          echo standard-error >&2
          return "$FAKE_STATUS"
        }
'''
        with tempfile.TemporaryDirectory() as directory:
            for status, expected_result in ((0, "ok"), (17, "FAILED")):
                result = subprocess.run(
                    ["bash", "--noprofile", "--norc", "-eo", "pipefail", "-c", fake_cargo + script],
                    cwd=root,
                    env=dict(os.environ, RUNNER_TEMP=directory, FAKE_STATUS=str(status)),
                    capture_output=True, text=True,
                )
                self.assertEqual(result.returncode, status, result.stderr)
                self.assertIn("standard-output\nstandard-error\n", result.stdout)
                self.assertEqual(result.stdout.count("Running unittests"), 1)
                self.assertFalse((Path(directory) / "workspace-tests.log").exists())
                with (Path(directory) / "test-binary-timings.csv").open(newline="", encoding="utf-8") as handle:
                    rows = list(csv.DictReader(handle))
                self.assertEqual(len(rows), 1)
                self.assertEqual(rows[0]["binary"], "qid_worker-ab12")
                self.assertEqual(rows[0]["result"], expected_result)


if __name__ == "__main__":
    unittest.main()
