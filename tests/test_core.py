"""Tests for read-only scanners and clone URL validation."""

from pathlib import Path
import unittest
from unittest.mock import patch

from sniffdog.clone import safe_clone
from sniffdog.scanner import run_all
from sniffdog.scanner.vscode import strip_jsonc


ROOT = Path(__file__).resolve().parents[1] / "demo-repos"


class CoreTests(unittest.TestCase):
    def test_safe_assignment_has_no_findings(self):
        self.assertEqual(run_all(ROOT / "safe-assignment"), [])

    def test_suspicious_assignment_detects_planted_signals(self):
        findings = run_all(ROOT / "suspicious-assignment")
        rules = {finding.rule for finding in findings}
        self.assertTrue({"package-script", "vscode-folder-open", "obfuscated-names",
                         "encoded-code", "dynamic-evaluation", "process-execution",
                         "raw-ip-url", "hidden-code", "disguised-asset", "asset-evaluation",
                         "npm-registry", "remote-dependency", "typosquat"} <= rules)
        self.assertIn("high", {finding.severity for finding in findings})
        self.assertTrue(all(finding.line is not None for finding in findings))

    def test_jsonc_preserves_string_and_trailing_commas(self):
        source = '{"url":"https://example.com/a,}", // comment\n "tasks":[{"command":"echo",},],}'
        import json
        parsed = json.loads(strip_jsonc(source))
        self.assertEqual(parsed["url"], "https://example.com/a,}")
        self.assertEqual(parsed["tasks"][0]["command"], "echo")

    def test_clone_rejects_unsafe_urls(self):
        with patch("sniffdog.clone.subprocess.run") as run:
            for url in ("git@github.com:a/b.git", "file:///tmp/a", "https://github.com/a/b;touch /tmp/x",
                        "https://github.com/a/b$(whoami)", "https://github.com/a/../b"):
                with self.subTest(url=url), self.assertRaises(ValueError):
                    safe_clone(url, Path("/tmp/unused"))
            run.assert_not_called()
