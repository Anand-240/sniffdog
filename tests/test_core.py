"""Tests for static scanning, local explanations and optional services."""

import base64
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from io import BytesIO
import json
from pathlib import Path
import tempfile
from threading import Thread
import unittest
from unittest.mock import patch

from sniffdog.clone import safe_clone
from sniffdog.cli import scan_target
from sniffdog.common import Finding, short
from sniffdog.github_info import inspect
from sniffdog.recruiter import search
from sniffdog.report import render
from sniffdog.scanner import run_all
from sniffdog.scanner.vscode import strip_jsonc
from sniffdog.tracing import before_send_transaction
from sniffdog.verdict import (CONSEQUENCES, explain, prepare_snippets, rule_verdict,
                              unwrap_payload, valid_code_sentence)


ROOT = Path(__file__).resolve().parents[1] / "demo-repos"


class CoreTests(unittest.TestCase):
    def test_safe_assignment_has_no_findings(self):
        self.assertEqual(run_all(ROOT / "safe-assignment"), [])
        self.assertEqual(rule_verdict([]), "safe")

    def test_suspicious_assignment_detects_planted_signals(self):
        findings = run_all(ROOT / "suspicious-assignment")
        self.assertEqual({item.rule for item in findings},
                         {"package-script", "vscode-folder-open", "obfuscated-names",
                          "encoded-code", "dynamic-evaluation", "process-execution",
                          "raw-ip-url", "hidden-code", "disguised-asset", "asset-evaluation",
                          "npm-registry", "remote-dependency", "typosquat"})
        self.assertEqual(rule_verdict(findings), "danger")
        self.assertTrue(all(item.line is not None for item in findings))
        self.assertIn("actually JavaScript code pretending to be a font/image",
                      next(item for item in findings if item.rule == "disguised-asset").message)

    def test_every_scanner_rule_has_a_plain_consequence(self):
        from sniffdog import github_info, recruiter
        from sniffdog.scanner import deps, disguised, obfuscation, scripts, vscode

        names = set()
        for module in (deps, disguised, obfuscation, scripts, vscode, github_info, recruiter):
            import re
            names.update(re.findall(r'(?:Finding|add)\("([a-z][a-z-]+)"', Path(module.__file__).read_text()))
        self.assertEqual(names - CONSEQUENCES.keys(), set())
        self.assertTrue(all(value.endswith(".") for value in CONSEQUENCES.values()))

    def test_static_decode_is_printable_and_capped_without_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "payload.js"
            message = b"console.log('safe');\n" * 12
            token = base64.b64encode(message).decode()
            path.write_text(f"const x = '{token}';\n")
            finding = Finding("encoded-code", "high", "payload.js", 1, short(token), "encoded")
            with patch("subprocess.run", side_effect=AssertionError("executed")):
                self.assertEqual(unwrap_payload(root, finding), message.decode())
            snippets = prepare_snippets(root, [finding])
            self.assertTrue(snippets[0]["code"].startswith("console.log('safe');"))
            self.assertLessEqual(len(snippets[0]["code"]), 121)
            self.assertTrue(snippets[0]["code"].endswith("…"))
            self.assertEqual(snippets[0]["unwrapped_from"], "base64")

            escaped = "\\x41" * 40
            path.write_text(f"const x = '{escaped}';\n")
            finding = Finding("encoded-code", "high", "payload.js", 1, short(escaped), "encoded")
            self.assertEqual(unwrap_payload(root, finding), "A" * 40)

            for binary in (b"A" * 4097, b"\0" * 180):
                token = base64.b64encode(binary).decode()
                path.write_text(f"const x = '{token}';\n")
                finding = Finding("encoded-code", "high", "payload.js", 1, short(token), "encoded")
                self.assertIsNone(unwrap_payload(root, finding))

    def test_url_grounding_and_completed_harm(self):
        snippet = "curl https://example.com/a && echo 203.0.113.10"
        self.assertTrue(valid_code_sentence("It contacts the server at https://example.com/a.", snippet))
        self.assertTrue(valid_code_sentence("It contacts the example.com server.", snippet))
        self.assertFalse(valid_code_sentence("It contacts https://other.example/a.", snippet))
        self.assertFalse(valid_code_sentence("It contacts 203.0.113.11.", snippet))
        self.assertTrue(valid_code_sentence("It runs the Node.js script.", "node setup.js"))
        self.assertFalse(valid_code_sentence("hello", "echo hello"))
        self.assertFalse(valid_code_sentence("Your system is compromised.", snippet))
        self.assertFalse(valid_code_sentence("The script has infected your computer.", snippet))
        self.assertFalse(valid_code_sentence("Report the account to the recruiter.", snippet))
        self.assertFalse(valid_code_sentence(" ".join(["word"] * 36), snippet))

    def test_local_ollama_only_reads_snippets_and_cannot_lower_verdict(self):
        requests = []

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                requests.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
                body = json.dumps({"message": {"content": json.dumps({
                    "verdict": "safe", "sentence": "It prints a harmless message."})}}).encode()
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
            with patch.dict("os.environ", {"OLLAMA_HOST": f"http://127.0.0.1:{server.server_port}",
                                        "MONGODB_URI": "", "SENTRY_DSN": ""}):
                result, findings, used_llm, github, error, notes, tracing = scan_target(
                    str(ROOT / "suspicious-assignment"), False, "hinglish", None, None)
            self.assertEqual(result["verdict"], "danger")
            self.assertTrue(used_llm)
            self.assertEqual(len(requests), 3)
            for request in requests:
                self.assertEqual(request["options"], {"temperature": 0, "num_ctx": 4096})
                self.assertIn("sentence", request["format"]["required"])
                self.assertIn("Hinglish", request["messages"][0]["content"])
                snippet = request["messages"][1]["content"]
                self.assertLessEqual(len(snippet.splitlines()) - 1, 40)
                self.assertLessEqual(len(snippet), 4200)
                self.assertGreaterEqual(len(snippet.splitlines()[1].strip()), 25)
            output = render("demo", result, findings, used_llm, github, notes, error, tracing)
            self.assertIn("Explainer: Gemma (local) read 3 snippets", output)
            self.assertIn("lib/config.js:7 (encoded-code) — unwrapped from base64:", output)
            self.assertNotIn("Hidden payload unwrapped", output)
            self.assertEqual(output.count("    Gemma:"), 3)
            self.assertNotIn(".vscode/tasks.json:10 (vscode-folder-open):\n    echo hello\n    Gemma:", output)
            self.assertTrue(all(item["source"] == "rule" for item in result["what_this_means"]))
        finally:
            server.shutdown()
            server.server_close()
            thread.join()

    def test_ollama_request_times_out_after_30_seconds(self):
        findings = run_all(ROOT / "suspicious-assignment")
        snippets = [{"file_line": "package.json:6", "rule": "package-script",
                     "code": "node scripts/setup.js && echo hello"}]
        body = BytesIO(json.dumps({"message": {"content": '{"sentence":"It prints hello in the terminal."}'}}).encode())
        with patch.dict("os.environ", {"OLLAMA_HOST": "http://127.0.0.1:11434"}), \
                patch("sniffdog.verdict.urlopen", return_value=body) as fetch:
            result, used_llm = explain(findings, snippets)
        self.assertTrue(used_llm)
        self.assertEqual(result["verdict"], "danger")
        self.assertEqual(fetch.call_args.kwargs["timeout"], 30)

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

    def test_full_scan_without_optional_services_or_execution(self):
        with patch.dict("os.environ", {"MONGODB_URI": "", "SENTRY_DSN": ""}), \
                patch("subprocess.run", side_effect=AssertionError("executed")):
            verdict, findings, used_llm, github, error, notes, tracing = scan_target(
                str(ROOT / "suspicious-assignment"), True, "en", None, None)
        self.assertEqual(verdict["verdict"], "danger")
        self.assertFalse(used_llm)
        self.assertEqual(len(findings), 13)
        self.assertIsNone(notes)
        self.assertFalse(tracing)
        self.assertEqual(len(verdict["snippets"]), 5)
        self.assertEqual(sum("unwrapped_from" in item for item in verdict["snippets"]), 1)

    def test_tracing_drops_text_and_keeps_counts(self):
        event = {"event_id": "abc", "type": "transaction", "transaction": "scan",
                 "start_timestamp": "start", "timestamp": "end", "prompt": "private code",
                 "contexts": {"trace": {"trace_id": "id", "status": "ok", "secret": "code"}},
                 "spans": [{"op": "scripts", "description": "scripts", "data":
                            {"findings": 2, "prompt": "private code"}}]}
        clean = before_send_transaction(event, {})
        self.assertNotIn("private code", json.dumps(clean))
        self.assertEqual(clean["spans"][0]["data"], {"findings": 2})
