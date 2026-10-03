"""Tests for read-only scanners and clone URL validation."""

from pathlib import Path
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
import unittest
from unittest.mock import patch

from sniffdog.clone import safe_clone
from sniffdog.scanner import run_all
from sniffdog.scanner.vscode import strip_jsonc
from sniffdog.verdict import explain, rule_verdict


ROOT = Path(__file__).resolve().parents[1] / "demo-repos"


class CoreTests(unittest.TestCase):
    def test_safe_assignment_has_no_findings(self):
        self.assertEqual(run_all(ROOT / "safe-assignment"), [])
        self.assertEqual(rule_verdict([]), "safe")

    def test_suspicious_assignment_detects_planted_signals(self):
        findings = run_all(ROOT / "suspicious-assignment")
        rules = {finding.rule for finding in findings}
        self.assertEqual(rules, {"package-script", "vscode-folder-open", "obfuscated-names",
                                 "encoded-code", "dynamic-evaluation", "process-execution",
                                 "raw-ip-url", "hidden-code", "disguised-asset", "asset-evaluation",
                                 "npm-registry", "remote-dependency", "typosquat"})
        self.assertIn("high", {finding.severity for finding in findings})
        self.assertEqual(rule_verdict(findings), "danger")
        self.assertTrue(all(finding.line is not None for finding in findings))

    def test_ollama_cannot_lower_verdict(self):
        requests = []

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers["Content-Length"])
                requests.append(json.loads(self.rfile.read(length)))
                answer = {"message": {"content": json.dumps({
                    "verdict": "safe", "summary": "No risk", "reasons": ["None"],
                    "next_steps": ["Proceed"]})}}
                body = json.dumps(answer).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, format, *args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            findings = run_all(ROOT / "suspicious-assignment")
            with patch.dict("os.environ", {"OLLAMA_HOST": f"http://127.0.0.1:{server.server_port}"}):
                verdict, used_llm = explain(findings, {}, "hinglish")
            self.assertFalse(used_llm)
            self.assertEqual(verdict["verdict"], "danger")
            self.assertIn("suspicious signal", verdict["summary"])
            self.assertEqual(requests[0]["format"]["properties"]["verdict"]["enum"],
                             ["safe", "caution", "danger"])
            self.assertEqual(requests[0]["options"]["num_ctx"], 4096)
            self.assertIn("Hinglish", requests[0]["messages"][0]["content"])
        finally:
            server.shutdown()
            server.server_close()
            thread.join()

    def test_jsonc_preserves_string_and_trailing_commas(self):
        source = '{"url":"https://example.com/a,}", // comment\n "tasks":[{"command":"echo",},],}'
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
