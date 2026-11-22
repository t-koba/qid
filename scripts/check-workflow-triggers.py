#!/usr/bin/env python3
"""Fail if any workflow can start on a push to the integration branch.

CI on the integration branch (`mizu`) is request-only: a push there must not
start any workflow. Each workflow's top-level ``on.push`` is therefore required
to be absent, tag-only, or restricted to branches that do not include `mizu`.

This check is deliberately dependency-free so it can run in the CI Structure
job (and locally) without PyYAML. It parses only the small, fixed shape of the
repository's workflow ``on:`` blocks, and fails closed on anything it cannot
classify.
"""

import fnmatch
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WORKFLOWS = ROOT / ".github" / "workflows"
INTEGRATION_BRANCH = "mizu"


def indent(line):
    return len(line) - len(line.lstrip(" "))


def child_block(lines, key_index):
    """Indices of lines strictly more indented than the key, until dedent."""
    base = indent(lines[key_index])
    out = []
    for i in range(key_index + 1, len(lines)):
        if not lines[i].strip():
            continue
        if indent(lines[i]) <= base:
            break
        out.append(i)
    return out


def is_key(line, key):
    """Whether the stripped line is ``key:`` or ``key: <inline value>``."""
    text = line.strip()
    prefix = key + ":"
    if not text.startswith(prefix):
        return False
    rest = text[len(prefix):]
    return rest == "" or rest.startswith(" ")


def find_key(lines, indices, key):
    """Find a mapping key at the shallowest indent among ``indices``."""
    candidates = [i for i in indices if is_key(lines[i], key)]
    if not candidates:
        return None
    level = min(indent(lines[i]) for i in candidates)
    return next(i for i in candidates if indent(lines[i]) == level)


def scalar_items(lines, key_index):
    """Parse a key's value: inline ``[a, b]`` or a following ``- item`` list."""
    after = lines[key_index].strip().split(":", 1)[1].strip()
    if after.startswith("[") and after.endswith("]"):
        body = after[1:-1].strip()
        return [v.strip().strip("'\"") for v in body.split(",")] if body else []
    if after:
        # A single scalar branch/tag value.
        return [after.strip("'\"")]
    items = []
    base = indent(lines[key_index])
    for i in child_block(lines, key_index):
        if indent(lines[i]) != base + 2:
            continue
        text = lines[i].strip()
        if text.startswith("- "):
            items.append(text[2:].strip().strip("'\""))
    return items


def matches_integration(pattern):
    """Whether a branch glob could match the integration branch."""
    # Negation patterns (``!name``) invert a list and are outside this simple
    # positive matcher; callers fail closed on them.
    return not pattern.startswith("!") and fnmatch.fnmatchcase(INTEGRATION_BRANCH, pattern)


def push_problem(lines, on_children):
    """Return an error string if ``on.push`` can fire on the integration branch."""
    push_index = find_key(lines, on_children, "push")
    if push_index is None:
        return None
    push_children = child_block(lines, push_index)

    branches = find_key(lines, push_children, "branches")
    if branches is not None:
        patterns = scalar_items(lines, branches)
        negation = [p for p in patterns if p.startswith("!")]
        if negation:
            return f"push.branches uses negation patterns that cannot be verified: {negation}"
        bad = [p for p in patterns if matches_integration(p)]
        if bad:
            return f"push.branches matches {INTEGRATION_BRANCH}: {bad}"
        return None

    ignore = find_key(lines, push_children, "branches-ignore")
    if ignore is not None:
        patterns = scalar_items(lines, ignore)
        negation = [p for p in patterns if p.startswith("!")]
        if negation:
            return f"push.branches-ignore uses negation patterns that cannot be verified: {negation}"
        if not any(matches_integration(p) or p in ("*", "**") for p in patterns):
            return f"push.branches-ignore does not exclude {INTEGRATION_BRANCH}: {patterns}"
        return None

    # Tag-only pushes never fire for a branch push, so they cannot start on mizu.
    if find_key(lines, push_children, "tags") is not None:
        return None
    if find_key(lines, push_children, "tags-ignore") is not None:
        return None

    # A push with no branch/tag restriction fires on every branch, including mizu.
    return f"push has no branch/tag restriction, so it fires on {INTEGRATION_BRANCH}"


def check_file(path):
    lines = path.read_text(encoding="utf-8").splitlines()
    # Locate the shallowest top-level ``on:`` (YAML 1.1 reads bare 'on' as a bool,
    # but GitHub Actions treats it as the string key).
    on_keys = ("on", "'on'", '"on"')
    top = [
        i for i in range(len(lines))
        if any(is_key(lines[i], k) for k in on_keys)
    ]
    if not top:
        return None
    on_index = min(top, key=lambda i: indent(lines[i]))
    inline = lines[on_index].strip().split(":", 1)[1].strip()
    if inline:
        # Inline flow form (e.g. ``on: [push]``) is outside this parser's scope;
        # fail closed rather than risk missing a push trigger.
        return f"inline on: value cannot be verified: {inline}"
    return push_problem(lines, child_block(lines, on_index))


def main():
    files = sorted([*WORKFLOWS.glob("*.yml"), *WORKFLOWS.glob("*.yaml")])
    if not files:
        print(f"ERROR: no workflow files found in {WORKFLOWS}", file=sys.stderr)
        return 1
    problems = []
    for path in files:
        try:
            problem = check_file(path)
        except Exception as exc:  # fail closed on anything we cannot parse
            problem = f"could not parse triggers ({exc})"
        if problem:
            problems.append(f"{path.name}: {problem}")
    if problems:
        for problem in problems:
            print(f"ERROR: {problem}", file=sys.stderr)
        print(
            f"No workflow may start on a push to {INTEGRATION_BRANCH}; "
            "use a request-only trigger or restrict on.push.branches.",
            file=sys.stderr,
        )
        return 1
    print(f"OK: no workflow fires on push to {INTEGRATION_BRANCH} ({len(files)} files checked)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
