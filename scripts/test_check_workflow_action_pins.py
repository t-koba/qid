"""Regression tests for the workflow action-pinning guard.

Every case goes through check_file(), so both value classification and the
line-oriented structural layer are covered. The accepted/rejected choices
made by the checker (comments, quoting, local/docker refs) are asserted here.
"""

import importlib.util
import tempfile
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).with_name("check-workflow-action-pins.py")
_spec = importlib.util.spec_from_file_location("check_workflow_action_pins", MODULE_PATH)
guard = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(guard)

SHA = "3d3c42e5aac5ba805825da76410c181273ba90b1"


def file_verdict(workflow_text):
    """Return guard diagnostics for a temp workflow file."""
    with tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False) as handle:
        handle.write(workflow_text)
        path = Path(handle.name)
    try:
        return guard.check_file(path)
    finally:
        path.unlink()


def problem(uses_line):
    """Diagnostics for one ``uses:`` line in a minimal step."""
    return file_verdict("name: demo\njobs:\n  build:\n    steps:\n      - " + uses_line + "\n")


class WorkflowActionPinGuardTests(unittest.TestCase):
    def assert_rejected(self, uses_line):
        self.assertTrue(problem(uses_line), "expected a problem for: " + uses_line)

    def assert_allowed(self, uses_line):
        self.assertEqual([], problem(uses_line), "expected no problem for: " + uses_line)

    # Every ref currently in the repository is accepted, and the sweep is
    # not vacuous: it must actually see pinned remote uses entries.
    def test_all_workflow_files_are_pinned(self):
        files = sorted([*guard.WORKFLOWS.glob("*.yml"), *guard.WORKFLOWS.glob("*.yaml")])
        self.assertTrue(files)
        pinned = 0
        for path in files:
            self.assertEqual([], guard.check_file(path), path.name)
            for line in path.read_text(encoding="utf-8").splitlines():
                if guard.USES_KEY_RE.fullmatch(guard.strip_comment(line.strip())):
                    pinned += 1
        self.assertGreater(pinned, 0)

    # Mutable and malformed refs are rejected.
    def test_mutable_tag_rejected(self):
        self.assert_rejected("uses: actions/checkout@v7")
        self.assert_rejected("uses: actions/checkout@v7 # pinned?")

    def test_short_sha_rejected(self):
        self.assert_rejected(f"uses: actions/checkout@{SHA[:-1]}")

    def test_long_sha_rejected(self):
        self.assert_rejected(f"uses: actions/checkout@{SHA}0")

    def test_missing_owner_or_extra_path_rejected(self):
        self.assert_rejected(f"uses: checkout@{SHA}")
        self.assert_rejected(f"uses: actions/checkout/.github/workflows/ci.yml@{SHA}")

    def test_malformed_values_rejected(self):
        for value in ("", "# v7", "*pinned_ref", "|\n        " + SHA, f"{SHA} {SHA}"):
            with self.subTest(value=value):
                self.assertTrue(file_verdict(f"name: demo\njobs:\n  build:\n    steps:\n      - uses: {value}\n"))

    def test_flow_mapping_rejected(self):
        self.assert_rejected(f"uses: {{{{ uses: actions/checkout@v7 }}}}")

    def test_quoted_key_is_checked(self):
        self.assert_rejected('"uses": actions/checkout@v7')

    # Comments are annotation only: absent, blank or arbitrary text.
    def test_no_comment_accepted(self):
        self.assert_allowed(f"uses: actions/checkout@{SHA}")

    def test_blank_comment_accepted(self):
        self.assert_allowed(f"uses: actions/checkout@{SHA} #")
        self.assert_allowed(f"uses: actions/checkout@{SHA} #   ")

    def test_tag_comment_accepted(self):
        self.assert_allowed(f"uses: actions/checkout@{SHA} # v7")

    def test_uppercase_sha_accepted(self):
        self.assert_allowed(f"uses: actions/checkout@{SHA.upper()} # v7")

    # Local and docker uses entries cannot select a remote action.
    def test_local_action_ignored(self):
        self.assert_allowed("uses: ./ci/actions/local")

    def test_docker_action_ignored(self):
        self.assert_allowed("uses: docker://alpine:3.20")

    # Quoted values: remote refs are rejected explicitly, while quoted
    # local/docker refs are ignored per the checker docstring.
    def test_quoted_pinned_ref_rejected(self):
        verdict = problem(f'uses: "actions/checkout@{SHA}" # v7')
        self.assertTrue(verdict)
        self.assertIn("quoted", verdict[0])

    def test_quoted_mutable_ref_rejected(self):
        self.assert_rejected("uses: 'actions/checkout@v7'")

    def test_quoted_local_and_docker_ignored(self):
        self.assert_allowed("uses: './ci/actions/local'")
        self.assert_allowed("uses: 'docker://alpine:3.20'")

    # One diagnostic per problem, including the offending line.
    def test_each_bad_entry_gets_its_own_diagnostic(self):
        text = (
            "name: demo\njobs:\n  build:\n    steps:\n"
            f"      - uses: actions/checkout@v7\n"
            f"      - uses: actions/checkout@{SHA[:-1]}\n"
        )
        verdict = file_verdict(text)
        self.assertEqual(2, len(verdict))
        self.assertIn("line 5", verdict[0])
        self.assertIn("line 6", verdict[1])

    def test_workflow_without_uses_entries_allowed(self):
        self.assertEqual([], file_verdict("name: demo\njobs:\n  build:\n    runs-on: ubuntu-latest\n"))


if __name__ == "__main__":
    unittest.main()
