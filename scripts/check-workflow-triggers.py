#!/usr/bin/env python3
"""Fail if any workflow can start on a push to the integration branch.

CI on the integration branch (`mizu`) is request-only: a push there must not
start any workflow. Each workflow's top-level ``on.push`` is therefore required
to be absent, tag-only, or restricted to branches that do not include `mizu`.

This check is deliberately dependency-free so it can run in the CI Structure
job (and locally) without PyYAML. It recognises two explicit ``on:`` shapes:

* a mapping of event keys (``on:\\n  push:`` ...), where keys may be quoted;
* a sequence of event names (``on:\\n  - push``), indented or indentless.

Anything else -- an inline value, a flow map, an alias, mixed forms, an
unreadable key, or deeper content attached to a sequence event -- is rejected
rather than guessed. A ``push`` in sequence form has no verifiable branch or
tag filter (it fires on every branch) and is rejected. This keeps the guard
fail-closed: inability to establish the event structure can never mean "safe".
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
# A mapping/event key: identifier-like, so quoting can be normalised safely.
EVENT_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_-]*$")
COMMENT_RE = re.compile(r"(?:^|\s)#.*$")


class UnclassifiableValue(ValueError):
    """A structure this parser cannot classify with confidence."""


def indent(line):
    return len(line) - len(line.lstrip(" "))


def strip_comment(text):
    return COMMENT_RE.sub("", text).rstrip()


def meaningful(line):
    return bool(line.strip()) and not line.lstrip().startswith("#")


def unquote(token):
    token = token.strip()
    if len(token) >= 2 and token[0] == token[-1] and token[0] in "'\"":
        return token[1:-1]
    return token


def key_name(line):
    """Normalised mapping key of a ``name:`` line, or None if not a plain key."""
    text = strip_comment(line.strip())
    name, sep, rest = text.partition(":")
    if not sep:
        return None
    name = unquote(name)
    if not EVENT_RE.fullmatch(name):
        return None
    # The remainder is empty for ``name:`` or a value for ``name: value``;
    # a colon without a separating space is not this grammar.
    return name if (not rest or rest.startswith(" ")) else None


def is_key(line, key):
    """Whether the line is a mapping key equal to ``key`` after unquoting."""
    return key_name(line) == key


def child_block(lines, key_index):
    """Indices of lines strictly more indented than the key, until dedent.

    Comments are transparent to YAML structure regardless of column, so they
    are skipped rather than treated as a dedent.
    """
    base = indent(lines[key_index])
    out = []
    for i in range(key_index + 1, len(lines)):
        if not meaningful(lines[i]):
            continue
        if indent(lines[i]) <= base:
            break
        out.append(i)
    return out


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


def block_sequence_items(lines, key_index):
    """Read a YAML block sequence, including deeper and indentless forms."""
    base = indent(lines[key_index])
    items = []
    for i in range(key_index + 1, len(lines)):
        raw = lines[i]
        if not meaningful(raw):
            continue
        ind = indent(raw)
        text = strip_comment(raw.strip())
        if text.startswith("- ") or text == "-":
            if ind < base:
                break
            items.append(clean_token(text[2:].strip() if text.startswith("- ") else ""))
            continue
        if ind > base:
            raise UnclassifiableValue(f"unexpected nested line {raw.strip()!r}")
        break
    if not items:
        raise UnclassifiableValue("empty or missing block sequence")
    return items


def scalar_items(lines, key_index):
    """Parse a branches/branches-ignore/tags value into pattern strings."""
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
    # Negation patterns invert a list and are outside this positive matcher;
    # callers fail closed on them.
    return not pattern.startswith("!") and fnmatch.fnmatchcase(INTEGRATION_BRANCH, pattern)


def patterns_or_error(lines, key_index, label):
    try:
        return scalar_items(lines, key_index), None
    except UnclassifiableValue as exc:
        return [], f"push.{label} cannot be read ({exc})"


def push_problem(lines, push_index):
    """Return an error string if this ``push`` event can fire on mizu."""
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

    # Tag-only pushes never fire for a branch push, so they cannot start on
    # mizu -- but only once the filter value is known to be readable. Merely
    # seeing a tags key must not certify a restriction we have not established.
    tags = find_key(lines, push_children, "tags")
    if tags is not None:
        _, error = patterns_or_error(lines, tags, "tags")
        return error
    ignore_tags = find_key(lines, push_children, "tags-ignore")
    if ignore_tags is not None:
        _, error = patterns_or_error(lines, ignore_tags, "tags-ignore")
        return error

    # A push with no branch/tag restriction fires on every branch, including mizu.
    return f"push has no branch/tag restriction, so it fires on {INTEGRATION_BRANCH}"


def on_events(lines, on_index):
    """Return (form, entries) for the value of ``on:``.

    form is "mapping" (entries are ``(event_name, key_line_index)``) or
    "sequence" (entries are ``(None, event_name)``). Raises
    UnclassifiableValue for any shape outside the two explicit forms.
    """
    base = indent(lines[on_index])
    first = next((i for i in range(on_index + 1, len(lines)) if meaningful(lines[i])), None)
    if first is None:
        raise UnclassifiableValue("on: has no value")
    level = indent(lines[first])
    text = strip_comment(lines[first].strip())
    is_item = text == "-" or text.startswith("- ")

    if level < base or (level == base and not is_item):
        raise UnclassifiableValue("on: has no readable value")

    if is_item:
        entries = []
        for i in range(first, len(lines)):
            if not meaningful(lines[i]):
                continue
            ind = indent(lines[i])
            item_text = strip_comment(lines[i].strip())
            is_entry = item_text == "-" or item_text.startswith("- ")
            # A sibling top-level key ends the on: block. In the indentless
            # form level == base, so that key shares the items' indent and the
            # usual `ind < level` dedent test cannot see it.
            if ind <= base and not is_entry:
                break
            if ind != level or not is_entry:
                raise UnclassifiableValue(
                    f"unclassifiable content in on: sequence {item_text!r}"
                )
            name = unquote(item_text[1:].strip()) if item_text != "-" else ""
            if not EVENT_RE.fullmatch(name):
                raise UnclassifiableValue(f"unreadable on: event {item_text!r}")
            entries.append((None, name))
        if not entries:
            raise UnclassifiableValue("empty on: sequence")
        return "sequence", entries

    entries = []
    for i in range(first, len(lines)):
        if not meaningful(lines[i]):
            continue
        ind = indent(lines[i])
        if ind < level:
            break
        if ind > level:  # config nested under the preceding event key
            continue
        name = key_name(lines[i])
        if name is None:
            raise UnclassifiableValue(f"unreadable on: event key {lines[i].strip()!r}")
        entries.append((name, i))
    if not entries:
        raise UnclassifiableValue("empty on: mapping")
    return "mapping", entries


def analyze_on(lines, on_index):
    """Return an error string if ``on:`` can start a push on mizu, else None."""
    form, entries = on_events(lines, on_index)
    if form == "sequence":
        # A bare push event has no branch/tag filter we can verify.
        if any(name == "push" for _, name in entries):
            return "on: sequence includes push with no verifiable branch/tag restriction"
        return None
    for name, index in entries:
        if name == "push":
            return push_problem(lines, index)
    return None


def check_file(path):
    lines = path.read_text(encoding="utf-8").splitlines()
    # Trigger discovery is part of the supported grammar: a workflow must
    # declare a readable root-level ``on:`` key. Derive the root indent from
    # the shallowest significant line (comments and blanks are transparent),
    # then accept only ``on:`` keys at that level. A nested ``on:`` (e.g. under
    # ``jobs``) is not a workflow trigger and cannot stand in for the root key.
    significant = [i for i in range(len(lines)) if meaningful(lines[i])]
    if not significant:
        return "on: structure cannot be verified (no readable root on: key)"
    root_level = min(indent(lines[i]) for i in significant)
    top = [
        i for i in significant
        if indent(lines[i]) == root_level and is_key(lines[i], "on")
    ]
    if not top:
        return "on: structure cannot be verified (no readable root on: key)"
    on_index = top[0]
    inline = strip_comment(lines[on_index].strip().split(":", 1)[1]).strip()
    if inline:
        # Inline flow form (e.g. ``on: [push]`` or ``on: *events``) is outside
        # this parser's scope; fail closed rather than risk missing a trigger.
        return f"inline on: value cannot be verified: {inline}"
    try:
        return analyze_on(lines, on_index)
    except UnclassifiableValue as exc:
        return f"on: structure cannot be verified ({exc})"


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
