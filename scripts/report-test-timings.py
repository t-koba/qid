#!/usr/bin/env python3
"""Per-test wall-time inventory for the qid workspace (stdlib only).

Reads ``cargo test --no-run --message-format=json`` output, discovers test
executables from compiler-artifact records (``target.test`` and
``profile.test`` with an ``executable``), lists tests via each binary's
``--list`` flag, then runs every test individually with
``--exact --test-threads=1`` sequentially and records wall time.

Notes:
  * Every test runs in a fresh process. Wall times include startup and repeat
    per-process initialization, so rows are not additive or directly
    comparable with normal in-process suite timing.
  * Doctests are not timed: only compiled test executables discovered from
    Cargo JSON compiler-artifact lines are run; ``cargo test --doc`` output
    is never collected here.

Usage:
  cargo test --workspace --locked --no-run --message-format=json \\
    | python3 scripts/report-test-timings.py --output test-timings.csv
  python3 scripts/report-test-timings.py --input cargo.json --output out.csv
  python3 scripts/report-test-timings.py --target iga_routes --output /tmp/t.csv

Exit status is non-zero when test listing fails, when any test fails, or when
no test executables are discovered.
"""

import argparse
import csv
import json
import os
import subprocess
import sys
import time

CSV_HEADER = ["target", "test", "wall_seconds", "status"]
DEFAULT_TOP = 25
DEFAULT_MAX_FAILURES = 20
DEFAULT_MAX_FAILURE_LINES = 30


def parse_args(argv):
    parser = argparse.ArgumentParser(
        description="Run each libtest case individually and record wall times."
    )
    parser.add_argument(
        "--input",
        default=None,
        help="Cargo JSON log to read (default: stdin).",
    )
    parser.add_argument(
        "--output",
        "--csv",
        dest="output",
        default="test-timings.csv",
        help="Destination CSV path (default: test-timings.csv).",
    )
    parser.add_argument(
        "--summary",
        default=None,
        help="Markdown summary file to append (default: $GITHUB_STEP_SUMMARY when set).",
    )
    parser.add_argument(
        "--target",
        action="append",
        default=None,
        dest="targets",
        help="Only run test binaries with this target name (repeatable; local smoke tests).",
    )
    parser.add_argument(
        "--top",
        type=int,
        default=DEFAULT_TOP,
        help="Number of slowest tests shown in the summary table (default: 25).",
    )
    parser.add_argument(
        "--max-failures",
        type=int,
        default=DEFAULT_MAX_FAILURES,
        help="Maximum failing tests with printed detail (default: 20).",
    )
    return parser.parse_args(argv)


def read_lines(source):
    if source is None:
        data = sys.stdin.read().splitlines()
    else:
        with open(source, "r", encoding="utf-8") as handle:
            data = handle.read().splitlines()
    return data


def discover_binaries(lines, only_targets=None):
    binaries = []
    seen = set()
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if record.get("reason") != "compiler-artifact":
            continue
        target = record.get("target") or {}
        profile = record.get("profile") or {}
        executable = record.get("executable")
        if not target.get("test"):
            continue
        if not profile.get("test"):
            continue
        if not executable:
            continue
        name = target.get("name", "")
        if only_targets and name not in only_targets:
            continue
        key = (name, executable)
        if key in seen:
            continue
        seen.add(key)
        binaries.append(key)
    binaries.sort()
    return binaries


def list_tests(executable):
    proc = subprocess.run(
        [executable, "--list"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            "listing failed with exit {}: {}".format(
                proc.returncode, (proc.stderr or proc.stdout).strip()[-2000:]
            )
        )
    names = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if line.endswith(": test"):
            names.append(line[: -len(": test")].strip())
    return names


def classify(output, returncode, test_name):
    if returncode != 0:
        return "fail"
    prefix = "test {} ... ".format(test_name)
    result_lines = [
        line.strip()
        for line in output.splitlines()
        if line.strip().startswith(prefix)
    ]
    if len(result_lines) != 1:
        return "fail"
    result = result_lines[0][len(prefix) :]
    if result == "ok":
        return "pass"
    if result.startswith("ignored"):
        return "ignored"
    return "fail"


def main(argv=None):
    args = parse_args(argv if argv is not None else sys.argv[1:])
    only = set(args.targets) if args.targets else None

    lines = read_lines(args.input)
    binaries = discover_binaries(lines, only_targets=only)
    if not binaries:
        print("report-test-timings: no test executables discovered", file=sys.stderr)
        return 1

    rows = []
    failures = []
    listing_errors = []
    passed = 0
    failed = 0
    ignored = 0

    for target_name, executable in binaries:
        try:
            test_names = list_tests(executable)
        except Exception as exc:  # noqa: BLE001 - report and continue
            listing_errors.append((target_name, str(exc)[:2000]))
            continue
        for test_name in test_names:
            start = time.perf_counter()
            env = os.environ.copy()
            env["CARGO_TERM_COLOR"] = "never"
            proc = subprocess.run(
                [
                    executable,
                    test_name,
                    "--exact",
                    "--test-threads=1",
                    "--color",
                    "never",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                env=env,
            )
            elapsed = time.perf_counter() - start
            output = proc.stdout or ""
            status = classify(output, proc.returncode, test_name)
            rows.append((target_name, test_name, elapsed, status))
            if status == "pass":
                passed += 1
            elif status == "ignored":
                ignored += 1
            else:
                failed += 1
                failures.append((target_name, test_name, elapsed, output))

    rows.sort(key=lambda row: (row[0], row[1]))

    with open(args.output, "w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(CSV_HEADER)
        for target_name, test_name, elapsed, status in rows:
            writer.writerow([target_name, test_name, "{:.3f}".format(elapsed), status])

    total = len(rows)
    print(
        "report-test-timings: total={} pass={} fail={} ignored={} csv={}".format(
            total, passed, failed, ignored, args.output
        )
    )

    if listing_errors:
        print("report-test-timings: listing failures:", file=sys.stderr)
        for target_name, detail in listing_errors[: args.max_failures]:
            print("  {}: {}".format(target_name, detail), file=sys.stderr)

    show = failures[: max(0, args.max_failures)]
    for target_name, test_name, elapsed, output in show:
        print(
            "FAIL {}::{} ({:.3f}s)".format(target_name, test_name, elapsed),
            file=sys.stderr,
        )
        tail = output.splitlines()[-DEFAULT_MAX_FAILURE_LINES:]
        for out_line in tail:
            print("  | {}".format(out_line[:1000]), file=sys.stderr)
    if len(failures) > len(show):
        print(
            "... and {} more failure(s) omitted".format(len(failures) - len(show)),
            file=sys.stderr,
        )

    top_n = max(0, args.top)
    slowest = sorted(rows, key=lambda row: row[2], reverse=True)[:top_n]
    summary_lines = [
        "",
        "## Per-test timings (slowest {})".format(top_n),
        "",
        "Each row uses a fresh process: times include startup and repeat per-process initialization. "
        "Rows are not additive or directly comparable with the normal in-process suite; doctests are not timed.",
        "",
        "| target | test | wall_seconds | status |",
        "| --- | --- | ---: | --- |",
    ]
    for target_name, test_name, elapsed, status in slowest:
        summary_lines.append(
            "| {} | {} | {:.3f} | {} |".format(target_name, test_name, elapsed, status)
        )
    summary_lines.append("")
    summary_lines.append(
        "Total: {} tests ({} passed, {} failed, {} ignored). Full CSV: `{}`.".format(
            total, passed, failed, ignored, args.output
        )
    )
    summary_text = "\n".join(summary_lines) + "\n"
    print(summary_text)

    summary_path = args.summary or os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_path:
        try:
            with open(summary_path, "a", encoding="utf-8") as handle:
                handle.write(summary_text)
            print("report-test-timings: summary appended to {}".format(summary_path))
        except OSError as exc:
            print(
                "report-test-timings: cannot write summary {}: {}".format(
                    summary_path, exc
                ),
                file=sys.stderr,
            )
            return 1

    if listing_errors or failed:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
