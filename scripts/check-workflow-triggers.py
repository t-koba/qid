#!/usr/bin/env python3
"""Fail if any workflow can start on a push to the integration branch.

CI on the integration branch (`mizu`) is request-only: a push there must not
start any workflow. Each workflow's top-level ``on.push`` is therefore required
to be absent, tag-only, or restricted to branches that do not include `mizu`.

This check is deliberately dependency-free so it can run in the CI Structure
job (and locally) without PyYAML. It parses only the small, fixed shape of the
repository's workflow ``on:`` blocks. Any value it cannot classify with
confidence is treated as unsafe (the workflow is rejected), so a reformatting
edit cannot silently reintroduce a ``mizu`` push trigger.
"""

import fnmatch
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WORKFLOWS = ROOT / ".github" / "workflows"
INTEGRATION_BRANCH = "mizu"

# A branch/tag pattern this parser can confidently read: git refs plus the
# glob characters GitHub accepts. Anything else (YAML aliases, flow maps,
# block scalars, embedded comments) is rejected rather than guessed.
PATTERN_RE = re.compile(r"^[A-Za-z0-9_./+*?!-]+$")
COMMENT_RE = re.compile(r"(?:^|\s)#.*$")


class UnclassifiableValue(ValueError):
    """A branches/tags value whose meaning this parser cannot determine."""


def indent(line):
    return len(line) - len(line.lstrip(" "))


def child_block(lines, key_index):
    """Indices of lines strictly more indented than the key, until dedent."""
    base = indent(lines[key_index])
    out = []
    for i in range(key_index + 1, len(lines)):
        # YAML comments are transparent to structure regardless of their
        # column; a column-0 comment must not terminate the block early.
        if not lines[i].strip() or lines[i].lstrip().startswith("#"):
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


def clean_token(text):
    """Validate and unquote one pattern; raise if it is not classifiable."""
    token = text.strip().strip("'\"").strip()
    if not token or not PATTERN_RE.fullmatch(token):
        raise UnclassifiableValue(f"unrecognised pattern {text.strip()!r}")
    return token


def strip_comment(text):
    return COMMENT_RE.sub("", text).rstrip()


def block_sequence_items(lines, key_index):
    """Read a YAML block sequence, including deeper and indentless forms."""
    base = indent(lines[key_index])
    items = []
    for i in range(key_index + 1, len(lines)):
        raw = lines[i]
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        ind = indent(raw)
        text = strip_comment(raw.strip())
        if text.startswith("- ") or text == "-":
            # A sequence item may be deeper than the key, or at the same
            # indent (YAML's indentless-sequence form). A shallower one is a
            # separate list and does not belong to this key.
            if ind < base:
                break
            value = text[2:].strip() if text.startswith("- ") else ""
            items.append(clean_token(value))
            continue
        if ind > base:
            # A nested mapping/scalar we did not expect inside the value.
            raise UnclassifiableValue(f"unexpected nested line {raw.strip()!r}")
        # A sibling key (or dedent) ends this sequence.
        break
    if not items:
        raise UnclassifiableValue("empty or missing block sequence")
    return items


def scalar_items(lines, key_index):
    """Parse a branches/branches-ignore/tags value into pattern strings.

    Raises UnclassifiableValue for any shape that is not confidently readable,
    so callers never mistake an unparsed value for a safe (empty) list.
    """
    after = strip_comment(lines[key_index].strip().split(":", 1)[1]).strip()
    if not after:
        return block_sequence_items(lines, key_index)
    if after.startswith("["):
        if not after.endswith("]"):
            raise UnclassifiableValue(f"unterminated flow list {after!r}")
        body = after[1:-1].strip()
        if not body:
            raise UnclassifiableValue("empty flow list")
        return [clean_token(part) for part in body.split(",")]
    if after.startswith(("{", "&", "*", "|", ">")):
        raise UnclassifiableValue(f"unsupported value form {after!r}")
    return [clean_token(after)]


def matches_integration(pattern):
    """Whether a branch glob could match the integration branch."""
    # Negation patterns (``!name``) invert a list and are outside this simple
    # positive matcher; callers fail closed on them.
    return not pattern.startswith("!") and fnmatch.fnmatchcase(INTEGRATION_BRANCH, pattern)


def patterns_or_error(lines, key_index, label):
    """Return (patterns, error); error is set when the value is unreadable."""
    try:
        return scalar_items(lines, key_index), None
    except UnclassifiableValue as exc:
        return [], f"push.{label} cannot be read ({exc})"


def push_problem(lines, on_children):
    """Return an error string if ``on.push`` can fire on the integration branch."""
    push_index = find_key(lines, on_children, "push")
    if push_index is None:
        return None
    push_children = child_block(lines, push_index)

    branches = find_key(lines, push_children, "branches")
    if branches is not None:
        patterns, error = patterns_or_error(lines, branches, "branches")
        if error:
            return error
        negation = [p for p in patterns if p.startswith("!")]
        if negation:
            return f"push.branches uses negation patterns that cannot be verified: {negation}"
        bad = [p for p in patterns if matches_integration(p)]
        if bad:
            return f"push.branches matches {INTEGRATION_BRANCH}: {bad}"
        return None

    ignore = find_key(lines, push_children, "branches-ignore")
    if ignore is not None:
        patterns, error = patterns_or_error(lines, ignore, "branches-ignore")
        if error:
            return error
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
    # Locate the shallowest top-level ``on:`` (YAML 1.1 reads bare 'on' as a
    # bool, but GitHub Actions treats it as the string key).
    on_keys = ("on", "'on'", '"on"')
    top = [i for i in range(len(lines)) if any(is_key(lines[i], k) for k in on_keys)]
    if not top:
        return None
    on_index = min(top, key=lambda i: indent(lines[i]))
    inline = lines[on_index].strip().split(":", 1)[1].strip()
    if inline:
        # Inline flow form (e.g. ``on: [push]``) is outside this parser's
        # scope; fail closed rather than risk missing a push trigger.
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
