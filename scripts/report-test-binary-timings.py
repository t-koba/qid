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
    for line_number, raw in enumerate(lines, 1):
        line = ANSI.sub("", raw).strip()
        if line.startswith("Running "):
            if binary is not None:
                raise ValueError(
                    f"missing summary for {binary} before executable at line {line_number}"
                )
            match = RUNNING.fullmatch(line)
            if not match:
                raise ValueError(f"invalid Cargo executable line at line {line_number}")
            binary = match[1].replace("\\", "/").rsplit("/", 1)[-1]
            # Cargo executable names are identifiers, not arbitrary CSV cells.
            if not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]*", binary):
                raise ValueError(f"invalid executable basename at line {line_number}")
        elif line.startswith("Doc-tests "):
            if binary is not None:
                raise ValueError(
                    f"missing summary for {binary} before doc-tests at line {line_number}"
                )
            # Cargo may interleave doc-test markers with other targets' output.
            # Keep doc-test mode latched; an active executable still owns its
            # next summary.
            doctests = True
        elif line.startswith("test result:"):
            if binary is None:
                if doctests:
                    continue
                raise ValueError(f"libtest summary has no executable at line {line_number}")
            match = SUMMARY.fullmatch(line)
            if not match:
                raise ValueError(
                    f"malformed libtest summary for {binary} at line {line_number}"
                )
            result, passed, failed, ignored, measured, filtered, duration = match.groups()
            rows.append((binary, duration, result, passed, failed, ignored, measured, filtered))
            binary = None
    if binary is not None:
        raise ValueError(f"missing libtest summary for {binary} at end of capture")
    if not rows:
        raise ValueError("capture contains no binary timings")
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
    except (OSError, ValueError) as error:
        try:
            args.output.unlink(missing_ok=True)
        except OSError:
            pass  # The diagnostic below also covers an inaccessible output path.
        if isinstance(error, UnicodeError):
            detail = "captured output is not valid UTF-8"
        elif isinstance(error, OSError):
            detail = "capture or CSV file could not be accessed"
        else:
            # Parser errors are fixed, content-free categories; never echo a
            # path, test name, or raw line from the Cargo log.
            detail = str(error)
        print(f"Test binary timing report failed: {detail}.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
