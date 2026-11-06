#!/usr/bin/env python3
"""Extract libtest binary durations from a normal, serial Cargo workspace run.

No tests are run. Only executable basenames and libtest summary fields are saved;
paths, test names and raw output are not. Doc-test summaries have no executable
identity and are excluded. Missing/malformed summaries fail the report, including
binaries that abort before libtest can print a duration.
"""

import argparse
import csv
from pathlib import Path
import re
import sys


ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
RUNNING = re.compile(r"Running .+ \((.+)\)")
SUMMARY = re.compile(
    r"test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored; "
    r"(\d+) measured; (\d+) filtered out; finished in (\d+\.\d+)s"
)
FIELDS = ("binary", "duration_seconds", "result", "passed", "failed", "ignored",
          "measured", "filtered_out")


def parse_timings(lines):
    rows = []
    binary = None
    doctests = False
    for raw in lines:
        line = ANSI.sub("", raw).strip()
        if line.startswith("Running "):
            if binary is not None:
                raise ValueError("missing binary summary")
            match = RUNNING.fullmatch(line)
            if not match:
                raise ValueError("invalid Cargo executable line")
            binary = match[1].replace("\\", "/").rsplit("/", 1)[-1]
            # Cargo executable names are identifiers, not arbitrary CSV cells.
            if not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]*", binary):
                raise ValueError("invalid executable basename")
            doctests = False
        elif line.startswith("Doc-tests "):
            if binary is not None:
                raise ValueError("missing binary summary before doc-tests")
            doctests = True
        elif line.startswith("test result:"):
            if doctests:
                continue
            match = SUMMARY.fullmatch(line)
            if binary is None or not match:
                raise ValueError("unpaired or invalid libtest summary")
            result, passed, failed, ignored, measured, filtered, duration = match.groups()
            rows.append((binary, duration, result, passed, failed, ignored, measured, filtered))
            binary = None
    if binary is not None or not rows:
        raise ValueError("incomplete or empty binary timings")
    return rows


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        # Never leave a stale or partial CSV that could be uploaded as evidence.
        args.output.unlink(missing_ok=True)
        with args.input.open(encoding="utf-8") as source:
            rows = parse_timings(source)
        with args.output.open("w", newline="", encoding="utf-8") as output:
            writer = csv.writer(output)
            writer.writerow(FIELDS)
            writer.writerows(rows)
    except (OSError, ValueError):
        try:
            args.output.unlink(missing_ok=True)
        except OSError:
            pass  # The diagnostic below also covers an inaccessible output path.
        print("Test binary timing report failed: readable Cargo output with complete "
              "executable/summary pairs and a writable CSV path is required.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
