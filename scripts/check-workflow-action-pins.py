#!/usr/bin/env python3
"""Fail if a workflow uses a remote GitHub action not pinned to a full SHA.

CI must not silently run code selected by a mutable ref: every remote
``uses: owner/repo@<40-hex SHA>`` is allowed, and anything else is reported.
This is a dependency-free line scanner so it can run in the CI Structure job
locally as well as in CI.

Choices made explicit here (and covered by the tests):

* The invariant is the ref itself. A trailing ``# ...`` comment, conventionally
  recording the original mutable tag (e.g. ``# v7``), is documentation only:
  no comment, a blank comment and any comment text are all accepted.
* Quoted action refs are rejected rather than interpreted, since the scanner
  does not emulate YAML escape handling. Quoted local/docker refs are still
  ignored because they cannot select a remote action.
* Local (``./...``) and docker (``docker://...``) uses entries are ignored.
* Values that cannot be classified as one of the above -- blank values,
  aliases, flow mappings, block scalars, owner/repo paths, wrong-length hex,
  mutable tags, extra text -- fail closed with a diagnostic. The scanner is
  line-oriented, so a ``uses:``-shaped line inside a block scalar is also
  treated as a uses entry rather than guessed away.
"""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WORKFLOWS = ROOT / ".github" / "workflows"

COMMENT_RE = re.compile(r"(?:^|\s)#.*$")
USES_KEY_RE = re.compile(r"^(?:-\s+)?['\"]?uses['\"]?\s*:(?P<value>.*)$")
FLOW_USES_RE = re.compile(r"\{\s*['\"]?uses['\"]?\s*:")
REMOTE_RE = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@[0-9a-fA-F]{40}\Z")


def meaningful(line):
    return bool(line.strip()) and not line.lstrip().startswith("#")


def strip_comment(text):
    return COMMENT_RE.sub("", text).rstrip()


def ref_problem(value):
    """Diagnostic for one ``uses:`` value, or None when it is acceptable."""
    quoted = len(value) >= 2 and value[0] == value[-1] and value[0] in "'\""
    inner = value[1:-1] if quoted else value
    if inner.startswith("./") or inner.startswith("docker://"):
        return None
    if quoted:
        return f"quoted action ref cannot be verified: {value}"
    if not REMOTE_RE.fullmatch(value):
        return f"action ref is not owner/repo@<40-hex SHA>: {value!r}"
    return None


def check_file(path):
    """Return one diagnostic per unacceptable ``uses:`` entry in ``path``."""
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as exc:
        return [f"could not read file ({exc})"]
    problems = []
    for number, raw in enumerate(lines, 1):
        if not meaningful(raw):
            continue
        text = strip_comment(raw.strip())
        if not text:
            continue
        match = USES_KEY_RE.fullmatch(text)
        if match:
            value = match.group("value").strip()
            if not value:
                problems.append(f"line {number}: uses: has no readable value")
                continue
            problem = ref_problem(value)
            if problem:
                problems.append(f"line {number}: {problem}")
        elif FLOW_USES_RE.search(text):
            problems.append(f"line {number}: flow-style uses: cannot be verified: {text}")
    return problems


def main():
    files = sorted([*WORKFLOWS.glob("*.yml"), *WORKFLOWS.glob("*.yaml")])
    if not files:
        print(f"ERROR: no workflow files found in {WORKFLOWS}", file=sys.stderr)
        return 1
    problems = []
    for path in files:
        try:
            problems.extend(f"{path.name}: {problem}" for problem in check_file(path))
        except Exception as exc:  # fail closed on anything we cannot scan
            problems.append(f"{path.name}: could not scan uses: entries ({exc})")
    for problem in problems:
        print(f"ERROR: {problem}", file=sys.stderr)
    if problems:
        print(
            "All remote GitHub actions in workflows must be pinned to a full SHA.",
            file=sys.stderr,
        )
        return 1
    print(f"OK: all remote workflow actions are pinned to full SHAs ({len(files)} files checked)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
