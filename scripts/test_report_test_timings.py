"""Focused tests for per-test timing report CSV safety."""

import contextlib
import csv
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location(
    "test_timings_reporter", Path(__file__).with_name("report-test-timings.py")
)
reporter = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reporter)


class TestTimingReportTests(unittest.TestCase):
    def test_formula_like_csv_text_is_neutralized(self):
        formulae = [
            '=HYPERLINK("https://example.invalid","open")',
            "+1+1",
            "-1+1",
            "@SUM(1,1)",
            " \t\r=1+1",
        ]
        for value in formulae:
            with self.subTest(value=value):
                self.assertEqual(reporter.csv_text(value), "'" + value)
        for value in ("Build, Linux", "ordinary", ""):
            with self.subTest(value=value):
                self.assertEqual(reporter.csv_text(value), value)

    def test_formula_like_cargo_target_is_neutralized_in_csv(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            executable = root / "fake-test"
            executable.write_text(
                "#!/usr/bin/env python3\n"
                "import sys\n"
                "if sys.argv[1:] == ['--list']:\n"
                "    print('ordinary: test')\n"
                "elif len(sys.argv) > 1 and sys.argv[1] == 'ordinary':\n"
                "    print('test ordinary ... ok')\n"
                "else:\n"
                "    raise SystemExit(2)\n",
                encoding="utf-8",
            )
            executable.chmod(0o755)
            cargo_log = root / "cargo.json"
            cargo_log.write_text(
                json.dumps(
                    {
                        "reason": "compiler-artifact",
                        "target": {"test": True, "name": "-1"},
                        "profile": {"test": True},
                        "executable": str(executable),
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            output = root / "timings.csv"
            summary = root / "summary.md"
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(
                    reporter.main(
                        ["--input", str(cargo_log), "--output", str(output), "--summary", str(summary)]
                    ),
                    0,
                )
            with output.open(newline="", encoding="utf-8") as handle:
                row = next(csv.DictReader(handle))
            self.assertEqual(row["target"], "'-1")
            self.assertEqual(row["test"], "ordinary")
            self.assertEqual(row["status"], "pass")


if __name__ == "__main__":
    unittest.main()
