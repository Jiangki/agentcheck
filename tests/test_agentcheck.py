from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from agentcheck.rules import MAX_FILE_BYTES, run_rules
from agentcheck.scanner import scan_directory
GOOD_FIXTURE = PROJECT_ROOT / "fixtures" / "good-skill"
BAD_FIXTURE = PROJECT_ROOT / "fixtures" / "bad-skill"


def run_cli(*arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "agentcheck", *arguments],
        cwd=PROJECT_ROOT,
        text=True,
        capture_output=True,
        check=False,
    )


class AgentCheckAcceptanceTests(unittest.TestCase):
    def test_good_fixture_exits_zero_without_executing_code(self) -> None:
        execution_marker = GOOD_FIXTURE / "WAS_EXECUTED"
        self.assertFalse(execution_marker.exists())

        result = run_cli("check", str(GOOD_FIXTURE))

        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertIn("scanned 4 files", result.stdout)
        self.assertIn("No issues found.", result.stdout)
        self.assertFalse(execution_marker.exists())

    def test_bad_fixture_exits_one_with_rule_ids_and_paths(self) -> None:
        result = run_cli("check", str(BAD_FIXTURE))

        self.assertEqual(result.returncode, 1, result.stderr + result.stdout)
        for rule_id in (
            "META001",
            "META002",
            "REF001",
            "REF002",
            "SHELL001",
            "SHELL002",
            "PERM001",
        ):
            self.assertIn(rule_id, result.stdout)
        self.assertIn("SKILL.md:", result.stdout)
        self.assertIn("install.sh:", result.stdout)

    def test_json_output_is_machine_readable(self) -> None:
        result = run_cli("check", str(BAD_FIXTURE), "--json")

        self.assertEqual(result.returncode, 1, result.stderr + result.stdout)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["tool"], "agentcheck")
        self.assertGreater(payload["summary"]["errors"], 0)
        self.assertTrue(
            all(
                {"rule_id", "severity", "path", "line", "message", "hint"}
                <= finding.keys()
                for finding in payload["findings"]
            )
        )

    def test_missing_path_exits_two_without_traceback(self) -> None:
        missing = PROJECT_ROOT / "fixtures" / "does-not-exist"
        result = run_cli("check", str(missing))

        self.assertEqual(result.returncode, 2)
        self.assertIn("agentcheck: error:", result.stderr)
        self.assertIn("does not exist", result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_markdown_report_can_be_written(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            report = Path(temporary) / "report.md"
            result = run_cli(
                "check", str(GOOD_FIXTURE), "--output", str(report)
            )

            self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
            content = report.read_text(encoding="utf-8")
            self.assertIn("# AgentCheck report", content)
            self.assertIn("- Errors: 0", content)

    def test_size_and_symlink_rules_are_active(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "SKILL.md").write_text(
                "---\n"
                "description: Temporary test Skill.\n"
                "license: MIT\n"
                "---\n\n"
                "# Temporary Skill\n",
                encoding="utf-8",
            )
            (root / "large.txt").write_bytes(b"x" * (MAX_FILE_BYTES + 1))
            outside = root.parent / "{}-outside.txt".format(root.name)
            outside.write_text("outside\n", encoding="utf-8")
            link = root / "outside-link"
            try:
                try:
                    link.symlink_to(outside)
                except OSError as exc:
                    self.skipTest("symbolic links are unavailable: {}".format(exc))
                findings = run_rules(scan_directory(root))
            finally:
                outside.unlink(missing_ok=True)

            rule_ids = {finding.rule_id for finding in findings}
            self.assertIn("SIZE001", rule_ids)
            self.assertIn("PATH001", rule_ids)


if __name__ == "__main__":
    unittest.main()
