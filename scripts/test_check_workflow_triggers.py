"""Regression tests for the workflow push-trigger guard.

These run in the CI Structure job alongside the other scripts tests. The
reported fail-open shapes are covered explicitly: a reformat of a branches
list must not be able to silently reintroduce a push on the integration branch.
"""

import importlib.util
import tempfile
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).with_name("check-workflow-triggers.py")
_spec = importlib.util.spec_from_file_location("check_workflow_triggers", MODULE_PATH)
guard = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(guard)


def problem(on_block):
    """Return the guard verdict for a workflow's ``on:`` block text."""
    lines = on_block.strip("\n").splitlines()
    top = [i for i, line in enumerate(lines) if guard.is_key(line, "on")]
    on_index = min(top, key=lambda i: guard.indent(lines[i]))
    return guard.push_problem(lines, guard.child_block(lines, on_index))


def file_verdict(workflow_text):
    """Return the guard verdict end-to-end through check_file() on a temp file."""
    with tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False) as handle:
        handle.write(workflow_text)
        path = Path(handle.name)
    try:
        return guard.check_file(path)
    finally:
        path.unlink()


class WorkflowTriggerGuardTests(unittest.TestCase):
    def assert_rejected(self, on_block):
        self.assertIsNotNone(problem(on_block), "expected a problem for:\n" + on_block)

    def assert_allowed(self, on_block):
        self.assertIsNone(problem(on_block), "expected no problem for:\n" + on_block)

    # Reported fail-open reproductions: all must now be rejected.
    def test_deeper_indented_block_sequence(self):
        self.assert_rejected("on:\n  push:\n    branches:\n        - mizu\n")

    def test_indentless_block_sequence(self):
        self.assert_rejected("on:\n  push:\n    branches:\n    - mizu\n")

    def test_inline_list_with_trailing_comment(self):
        self.assert_rejected("on:\n  push:\n    branches: [main, mizu] # testing\n")

    # Previously working rejection controls stay rejected.
    def test_normal_block_sequence_mizu(self):
        self.assert_rejected("on:\n  push:\n    branches:\n      - mizu\n")

    def test_plain_inline_list_mizu(self):
        self.assert_rejected("on:\n  push:\n    branches: [main, mizu]\n")

    def test_glob_matching_integration(self):
        self.assert_rejected("on:\n  push:\n    branches: ['mizu*']\n")

    def test_negation_pattern(self):
        self.assert_rejected("on:\n  push:\n    branches: ['!foo']\n")

    def test_unrestricted_push(self):
        self.assert_rejected("on:\n  push:\n    paths: ['docs/**']\n")

    def test_branches_ignore_not_excluding_mizu(self):
        self.assert_rejected("on:\n  push:\n    branches-ignore: [main]\n")

    # Unclassifiable values fail closed.
    def test_empty_branches(self):
        self.assert_rejected("on:\n  push:\n    branches:\n")

    def test_flow_map(self):
        self.assert_rejected("on:\n  push:\n    branches: {mizu: x}\n")

    def test_yaml_alias(self):
        self.assert_rejected("on:\n  push:\n    branches: *anchor\n")

    def test_block_scalar(self):
        self.assert_rejected("on:\n  push:\n    branches: |\n      mizu\n")

    def test_unterminated_flow_list(self):
        self.assert_rejected("on:\n  push:\n    branches: [main, mizu\n")

    # Safe shapes stay allowed.
    def test_inline_list_main(self):
        self.assert_allowed("on:\n  push:\n    branches: [main]\n")

    def test_normal_block_sequence_main(self):
        self.assert_allowed("on:\n  push:\n    branches:\n      - main\n")

    def test_deeper_indented_sequence_main(self):
        self.assert_allowed("on:\n  push:\n    branches:\n        - main\n")

    def test_indentless_sequence_main(self):
        self.assert_allowed("on:\n  push:\n    branches:\n    - main\n")

    def test_inline_list_with_comment(self):
        self.assert_allowed("on:\n  push:\n    branches: [main] # ok\n")

    def test_branches_ignore_mizu(self):
        self.assert_allowed("on:\n  push:\n    branches-ignore: [mizu]\n")

    def test_tag_only_push(self):
        self.assert_allowed("on:\n  push:\n    tags: [v*]\n")

    def test_no_push_trigger(self):
        self.assert_allowed("on:\n  pull_request:\n")

    # check_file()/child_block() structural layer: YAML comments are
    # transparent to structure regardless of column.
    def test_column_zero_comment_in_on_block(self):
        workflow = (
            "name: demo\n"
            "on:\n"
            "# integration CI is request only\n"
            "  push:\n"
            "    branches: [mizu]\n"
            "jobs:\n"
            "  build:\n"
            "    runs-on: ubuntu-latest\n"
        )
        self.assertIsNotNone(file_verdict(workflow), workflow)

    def test_column_zero_comment_in_push_block(self):
        workflow = (
            "name: demo\n"
            "on:\n"
            "  push:\n"
            "# integration CI is request only\n"
            "    branches: [mizu]\n"
            "jobs:\n"
            "  build:\n"
            "    runs-on: ubuntu-latest\n"
        )
        self.assertIsNotNone(file_verdict(workflow), workflow)

    def test_column_zero_comment_safe_branches(self):
        workflow = (
            "name: demo\n"
            "on:\n"
            "# note\n"
            "  push:\n"
            "# note\n"
            "    branches: [main]\n"
            "jobs:\n"
            "  build:\n"
            "    runs-on: ubuntu-latest\n"
        )
        self.assertIsNone(file_verdict(workflow), workflow)

    # The real repository workflows are all compliant after the fix.
    def test_repository_workflows_are_compliant(self):
        files = sorted([*guard.WORKFLOWS.glob("*.yml"), *guard.WORKFLOWS.glob("*.yaml")])
        self.assertGreater(len(files), 0)
        for path in files:
            self.assertIsNone(guard.check_file(path), f"workflow failed guard: {path.name}")


if __name__ == "__main__":
    unittest.main()
