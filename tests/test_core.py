"""Tests for read-only scanners and clone URL validation."""

from pathlib import Path
from datetime import datetime, timedelta, timezone
from io import BytesIO
import json
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
import unittest
from unittest.mock import patch

from sniffdog.clone import safe_clone
from sniffdog.github_info import inspect
from sniffdog.recruiter import search
from sniffdog.report import render
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
        asset = next(finding for finding in findings if finding.rule == "disguised-asset")
        self.assertIn("actually JavaScript code pretending to be a font/image", asset.message)

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
            self.assertEqual(verdict["discard_reason"],
                             "model verdict safe is below rule verdict danger")
            self.assertEqual(len(requests), 2)
            self.assertEqual(requests[0]["format"]["properties"]["verdict"]["enum"],
                             ["safe", "caution", "danger"])
            self.assertIn("what_this_means", requests[0]["format"]["required"])
            self.assertEqual(requests[0]["options"]["num_ctx"], 4096)
            self.assertIn("Hinglish", requests[0]["messages"][0]["content"])
            sent = json.loads(requests[0]["messages"][1]["content"])["findings"]
            self.assertEqual(len(sent), 8)
            self.assertEqual(set(sent[0]), {"rule", "severity", "file:line", "message"})
            self.assertIn("Retry:", requests[1]["messages"][-1]["content"])
        finally:
            server.shutdown()
            server.server_close()
            thread.join()

    def test_model_bullets_match_finding_rule_and_location(self):
        findings = run_all(ROOT / "suspicious-assignment")
        answer = {"verdict": "danger", "summary": "These files have risky commands. Review them before running.",
                  "what_this_means": [
                      {"file_line": ".npmrc:1", "rule": "npm-registry",
                       "explanation": "This file reads a font."},
                      {"file_line": ".npmrc:1", "rule": "npm-registry",
                       "explanation": "This repo points npm at a nonstandard registry for packages."},
                      {"file_line": "lib/config.js:2", "rule": "asset-evaluation",
                       "explanation": "This line evaluates a font as code."},
                      {"file_line": "lib/config.js:2", "rule": "obfuscated-names",
                       "explanation": "These obfuscated-style names make the variables hard to read."},
                      {"file_line": ".vscode/tasks.json:10", "rule": "vscode-folder-open",
                       "explanation": "This task runs automatically when you open the folder in VS Code."}],
                  "next_steps": ["Report the account to the platform."]}
        body = json.dumps({"message": {"content": json.dumps(answer)}}).encode()
        with patch.dict("os.environ", {"OLLAMA_HOST": "http://127.0.0.1:11434"}), \
                patch("sniffdog.verdict.urlopen", side_effect=lambda *_args, **_kwargs: BytesIO(body)):
            verdict, used_llm = explain(findings, {}, "en")
        self.assertTrue(used_llm)
        known = {(f"{item.file}:{item.line}", item.rule) for item in findings}
        self.assertTrue(all((item["file_line"], item["rule"]) in known
                            for item in verdict["what_this_means"]))
        self.assertNotIn(("lib/config.js:2", "asset-evaluation"),
                         {(item["file_line"], item["rule"]) for item in verdict["what_this_means"]})
        self.assertEqual(len(verdict["what_this_means"]), 3)
        section = render("demo", verdict, findings, used_llm).split("What this means:\n", 1)[1]
        section = section.split("Next steps:", 1)[0]
        for line in section.splitlines():
            match = re.match(r"  - (.+:\d+) \(([\w-]+)\):", line)
            self.assertIsNotNone(match)
            self.assertIn(match.groups(), known)

    def test_model_advice_cannot_send_user_to_recruiter(self):
        findings = run_all(ROOT / "suspicious-assignment")
        answer = {"verdict": "danger", "summary": "These files have risky commands. Review them before running.",
                  "what_this_means": [], "next_steps": ["Report the account to the recruiter."]}
        body = json.dumps({"message": {"content": json.dumps(answer)}}).encode()
        with patch.dict("os.environ", {"OLLAMA_HOST": "http://127.0.0.1:11434"}), \
                patch("sniffdog.verdict.urlopen", side_effect=lambda *_args, **_kwargs: BytesIO(body)) as fetch:
            verdict, used_llm = explain(findings, {}, "en")
        self.assertFalse(used_llm)
        self.assertEqual(fetch.call_count, 2)
        self.assertEqual(verdict["discard_reason"], "answer advised contacting the recruiter")
        self.assertIn("LinkedIn", " ".join(verdict["next_steps"]))

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

    def test_github_metadata_adds_age_and_commit_findings(self):
        now = datetime.now(timezone.utc)
        def created(days):
            return (now - timedelta(days=days)).isoformat()
        responses = []
        for data in ({"created_at": created(3), "stargazers_count": 0},
                     {"created_at": created(30), "public_repos": 1}, [{}]):
            response = BytesIO(json.dumps(data).encode())
            response.headers = {"Link": '<https://api.github.com/repos/a/b/commits?per_page=1&page=2>; rel="last"'}
            responses.append(response)
        with patch("sniffdog.github_info.urlopen", side_effect=responses) as fetch:
            facts, findings = inspect("https://github.com/a/b")
        self.assertEqual(facts["commits"], 2)
        self.assertEqual({finding.rule for finding in findings},
                         {"new-github-owner", "few-commits", "new-github-repo", "little-github-history"})
        self.assertEqual(fetch.call_count, 3)
        with patch("sniffdog.github_info.urlopen") as fetch:
            self.assertEqual(inspect("https://example.com/a/b"), ({}, []))
            fetch.assert_not_called()

    def test_recruiter_search_requires_name_and_key(self):
        with patch.dict("os.environ", {"SERPAPI_API_KEY": ""}):
            self.assertEqual(search("Acme", None), ([], [], None))
        result = {"organic_results": [{"title": "Acme fake recruiter report",
                                       "link": "https://example.com/report",
                                       "snippet": "Acme scam warning"}]}
        responses = [BytesIO(json.dumps(result).encode()) for _ in range(2)]
        with patch.dict("os.environ", {"SERPAPI_API_KEY": "test"}), \
                patch("sniffdog.recruiter.urlopen", side_effect=responses):
            results, findings, error = search("Acme", None)
        self.assertIsNone(error)
        self.assertEqual(len(results), 2)
        self.assertEqual(len(findings), 2)
        self.assertTrue(all(finding.severity == "medium" for finding in findings))
