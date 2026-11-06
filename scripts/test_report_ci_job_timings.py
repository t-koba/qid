"""Focused stdlib tests: python3 -m unittest discover -s scripts -p 'test_report_ci_job_timings.py'."""

import csv
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location(
    "timings", Path(__file__).with_name("report-ci-job-timings.py")
)
timings = importlib.util.module_from_spec(spec)
spec.loader.exec_module(timings)


def job(**changes):
    return dict({"id": 1, "name": "Build", "status": "completed", "conclusion": "success",
                 "started_at": "2026-11-01T10:00:00Z", "completed_at": "2026-11-01T10:01:30Z"},
                **changes)


class JobTimingsTests(unittest.TestCase):
    def test_durations_and_partial_coverage(self):
        self.assertEqual(timings.elapsed_seconds(job()), 90)
        self.assertEqual(timings.elapsed_seconds(job(completed_at="2026-11-01T11:01:30+01:00")), 90)
        self.assertIsNone(timings.elapsed_seconds(job(started_at=None)))
        self.assertEqual(timings.elapsed_seconds(job(completed_at="2026-11-01T10:00:00Z")), 0)
        for value in (None, "invalid", "2026-11-01T09:00:00Z", "2026-11-01T10:01:30"):
            self.assertIsNone(timings.elapsed_seconds(job(completed_at=value)))
        with tempfile.TemporaryDirectory() as directory:
            output, summary = Path(directory) / "jobs.csv", Path(directory) / "summary.md"
            timings.write_report([job(), job(id=2, completed_at=None, conclusion="cancelled")],
                                 output, summary, 42, 2, "Test", "a" * 40)
            text = summary.read_text()
            self.assertIn("Workflow Test, run 42, attempt 2, head SHA " + "a" * 40, text)
            self.assertIn("Jobs API coverage: 2/2", text)
            self.assertIn("Timestamp coverage: 1/2", text)
            self.assertIn("90.000 seconds / 1.500000 job-minutes", text)
            self.assertIn("Not billing or workflow elapsed time", text)
            with output.open(newline="") as handle:
                rows = list(csv.DictReader(handle))
            self.assertEqual(rows[1]["observed_seconds"], "unavailable")
            self.assertEqual(rows[1]["conclusion"], "cancelled")
            timings.write_report([job(completed_at=None)], output, summary, 42, 2, "Test", "a" * 40)
            self.assertIn("durations): unavailable.", summary.read_text())

    def test_untrusted_names_are_single_line_and_escaped(self):
        name = '<img src=x>|[link](url)*`\\\n\r\x00\u202ehidden'
        escaped = timings.markdown(name)
        self.assertEqual(timings.normalized("a\n\t\x00b"), "a b")
        for unsafe in ("<", ">", "|", "[", "]", "*", "`", "\\", "\n", "\r", "\x00", "\u202e"):
            self.assertNotIn(unsafe, escaped)
        self.assertIn("&lt;img", escaped)
        self.assertIn("&#124;", escaped)

    def test_csv_formula_text_is_neutralized(self):
        names = ['=HYPERLINK("https://example.invalid","open")',
                 "+1+1", "-1+1", "@SUM(1,1)", " \t\r=1+1", "Build, Linux", ""]
        with tempfile.TemporaryDirectory() as directory:
            output, summary = Path(directory) / "jobs.csv", Path(directory) / "summary.md"
            timings.write_report([job(id=index, name=name) for index, name in enumerate(names)],
                                 output, summary, 42, 2, "Test", "a" * 40)
            with output.open(newline="") as handle:
                rows = list(csv.DictReader(handle))
            for row, name in zip(rows, names):
                expected = timings.normalized(name)
                if name not in ("Build, Linux", ""):
                    expected = "'" + expected
                self.assertEqual(row["job_name"], expected)
                self.assertEqual([row[key] for key in ("workflow_name", "run_id", "run_attempt",
                                                      "head_sha", "status", "conclusion",
                                                      "observed_seconds", "observed_minutes")],
                                 ["Test", "42", "2", "a" * 40, "completed", "success", "90.000", "1.500000"])
            timings.write_report([job(status="-1+1", conclusion="@SUM(1,1)")],
                                 output, summary, 42, 2, "=1+1", "+1+1")
            with output.open(newline="") as handle:
                row = next(csv.DictReader(handle))
            for key, value in (("workflow_name", "=1+1"), ("head_sha", "+1+1"),
                               ("status", "-1+1"), ("conclusion", "@SUM(1,1)")):
                self.assertEqual(row[key], "'" + value)

    @patch.object(timings, "urlopen")
    def test_pagination_covers_total_and_pins_attempt(self, opener):
        # A short first page must not terminate collection before total_count.
        opener.side_effect = [io.StringIO(json.dumps(payload)) for payload in (
            {"total_count": 3, "jobs": [job(), job(id=2)]},
            {"total_count": 3, "jobs": [job(id=3)]},
        )]
        self.assertEqual(len(timings.fetch_jobs("https://api.github.com", "owner/repo", 42, 2, "test-token")), 3)
        self.assertEqual(opener.call_count, 2)
        for page, call in enumerate(opener.call_args_list, 1):
            request = call.args[0]
            self.assertEqual(request.full_url,
                             f"https://api.github.com/repos/owner/repo/actions/runs/42/attempts/2/jobs?per_page=100&page={page}")
            self.assertEqual(request.get_header("Authorization"), "Bearer test-token")

    @patch.object(timings, "urlopen")
    def test_incomplete_pagination_fails_instead_of_claiming_coverage(self, opener):
        opener.side_effect = [io.StringIO(json.dumps(payload)) for payload in (
            {"total_count": 2, "jobs": [job()]}, {"total_count": 2, "jobs": [job()]},
        )]
        with self.assertRaisesRegex(ValueError, "incomplete"):
            timings.fetch_jobs("https://api.github.com", "owner/repo", 42, 1, "test-token")

    @patch.object(timings, "fetch_jobs")
    def test_event_guard_and_errors_do_not_log_token(self, fetch):
        with tempfile.TemporaryDirectory() as directory:
            event = Path(directory) / "event.json"
            run = {"repository": {"full_name": "owner/repo"}, "head_sha": "a" * 40,
                   "head_repository": {"full_name": "fork/repo"},
                   "name": "CI", "status": "completed", "id": 42, "run_attempt": 2}
            event.write_text(json.dumps({"workflow_run": run}))
            with patch.dict(os.environ, {"GITHUB_EVENT_PATH": str(event),
                                        "GITHUB_REPOSITORY": "owner/repo",
                                        "GITHUB_API_URL": "https://api.github.com",
                                        "GITHUB_TOKEN": "dummy-sensitive-value"}), patch.object(
                    timings.sys, "argv", ["reporter", "--output", str(Path(directory) / "jobs.csv"),
                                          "--summary", str(Path(directory) / "summary.md")]), patch.object(
                    timings.sys, "stderr", new_callable=io.StringIO) as errors:
                self.assertEqual(timings.main(), 1)
                fetch.assert_not_called()
                run["head_repository"]["full_name"] = "owner/repo"
                event.write_text(json.dumps({"workflow_run": run}))
                fetch.side_effect = RuntimeError("dummy-sensitive-value")
                self.assertEqual(timings.main(), 1)
                self.assertNotIn("dummy-sensitive-value", errors.getvalue())


if __name__ == "__main__":
    unittest.main()
