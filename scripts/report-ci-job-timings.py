#!/usr/bin/env python3
"""Report one completed GitHub Actions run attempt using only Jobs API timestamps.

Stdlib only. GITHUB_TOKEN is read from the environment, never logged. Missing,
invalid, timezone-less or reversed timestamps are unavailable, not zero. The
observed sum excludes unavailable durations; it is neither billing nor workflow
elapsed time (jobs may overlap, and setup/teardown may not be represented).
"""

import argparse
import csv
from datetime import datetime
import html
import json
import os
from pathlib import Path
import re
import sys
import unicodedata
from urllib.request import Request, urlopen


def elapsed_seconds(job):
    try:
        start, end = (
            datetime.fromisoformat(job[key].replace("Z", "+00:00"))
            for key in ("started_at", "completed_at")
        )
        if start.tzinfo is None or end.tzinfo is None or end < start:
            return None
        return (end - start).total_seconds()
    except (KeyError, TypeError, ValueError, AttributeError):
        return None


def normalized(value):
    return " ".join(
        "".join(
            " " if unicodedata.category(char).startswith("C") else char
            for char in str(value)
        ).split()
    )


def markdown(value):
    text = html.escape(normalized(value), quote=True)
    return re.sub(r"[\\`*_{}\[\]()#+.!|~-]", lambda match: f"&#{ord(match[0])};", text)


def csv_text(value):
    text = str(value)
    # CSV quoting does not stop spreadsheets from evaluating formula cells.
    return "'" + text if normalized(text).startswith(("=", "+", "-", "@")) else text


def fetch_jobs(api_url, repository, run_id, attempt, token):
    # 100 is the Jobs API's maximum page size, not a reporting cap.
    base = f"{api_url}/repos/{repository}/actions/runs/{run_id}/attempts/{attempt}/jobs"
    jobs = {}
    page = 1
    total = None
    while True:
        request = Request(
            f"{base}?per_page=100&page={page}",
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {token}",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        with urlopen(request) as response:
            payload = json.load(response)
        count = payload["total_count"]
        if not isinstance(count, int) or count < 0 or (total is not None and count != total):
            raise ValueError("inconsistent Jobs API count")
        total = count
        previous = len(jobs)
        for job in payload["jobs"]:
            jobs[job["id"]] = job
        if len(jobs) == total:
            return list(jobs.values())
        if len(jobs) > total or len(jobs) == previous:
            raise ValueError("incomplete Jobs API pagination")
        page += 1


def write_report(jobs, output, summary, run_id, attempt, workflow_name, head_sha):
    durations = [elapsed_seconds(job) for job in jobs]
    available = [value for value in durations if value is not None]
    total = sum(available) if available else None
    with Path(output).open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["workflow_name", "run_id", "run_attempt", "head_sha",
                         "job_name", "status", "conclusion", "observed_seconds", "observed_minutes"])
        for job, seconds in zip(jobs, durations):
            writer.writerow([
                csv_text(workflow_name), run_id, attempt, csv_text(head_sha),
                csv_text(normalized(job["name"])), csv_text(job["status"]),
                csv_text(job.get("conclusion") or "unavailable"),
                "unavailable" if seconds is None else f"{seconds:.3f}",
                "unavailable" if seconds is None else f"{seconds / 60:.6f}",
            ])
    lines = [
        "## CI job timings",
        f"Workflow {markdown(workflow_name)}, run {run_id}, attempt {attempt}, "
        f"head SHA {head_sha}. Jobs API coverage: {len(jobs)}/{len(jobs)} jobs fetched.",
        f"Timestamp coverage: {len(available)}/{len(jobs)} jobs with usable start/end timestamps.",
        "Observed runner-wall time (sum of available job durations): " + (
            "unavailable." if total is None else f"{total:.3f} seconds / {total / 60:.6f} job-minutes."
        ),
        "Not billing or workflow elapsed time. Jobs can overlap; unavailable durations are excluded, not zero. "
        "Only started_at/completed_at are used; setup/teardown may not be represented.",
        "",
        "| Job | Status | Conclusion | Observed seconds | Observed minutes |",
        "| --- | --- | --- | ---: | ---: |",
    ]
    for job, seconds in zip(jobs, durations):
        duration = "unavailable | unavailable" if seconds is None else f"{seconds:.3f} | {seconds / 60:.6f}"
        lines.append(
            f"| {markdown(job['name'])} | {markdown(job['status'])} | "
            f"{markdown(job.get('conclusion') or 'unavailable')} | {duration} |"
        )
    with Path(summary).open("a", encoding="utf-8") as handle:
        handle.write("\n".join(lines) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    parser.add_argument("--summary", default=os.environ.get("GITHUB_STEP_SUMMARY"), required=False)
    args = parser.parse_args()
    if not args.summary:
        parser.error("--summary or GITHUB_STEP_SUMMARY is required")
    try:
        event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text(encoding="utf-8"))
        run = event["workflow_run"]
        repository = os.environ["GITHUB_REPOSITORY"]
        if (run["repository"]["full_name"] != repository
                or (run.get("head_repository") or {}).get("full_name") != repository
                or run["name"] not in ("CI", "Test") or run["status"] != "completed"
                or not re.fullmatch(r"[0-9a-f]{40,64}", run["head_sha"])):
            raise ValueError("unexpected upstream run")
        jobs = fetch_jobs(os.environ["GITHUB_API_URL"], repository,
                          run["id"], run["run_attempt"], os.environ["GITHUB_TOKEN"])
        write_report(jobs, args.output, args.summary, run["id"], run["run_attempt"],
                     run["name"], run["head_sha"])
    except Exception:
        # Do not render exceptions, response bodies, request headers or tokens.
        print("CI job timing report failed; API access, complete pagination and valid event data are required.",
              file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
