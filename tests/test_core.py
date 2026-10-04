"""Tests for static scanning, local explanations and optional services."""

import base64
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from io import BytesIO, StringIO
import json
from pathlib import Path
import tempfile
from threading import Thread
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
from urllib.error import URLError

from sniffdog.clone import safe_clone
from sniffdog.cli import main, scan_target
from sniffdog.common import Finding, short
from sniffdog.github_info import inspect
from sniffdog.recruiter import search
from sniffdog.report import render
from sniffdog.scanner import run_all
from sniffdog.scanner.vscode import strip_jsonc
from sniffdog.tracing import before_send_transaction
from sniffdog.verdict import (CONSEQUENCES, explain, fallback, prepare_snippets, rule_verdict,
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

    def test_cli_excludes_demo_repos_from_root_scan(self):
        output = StringIO()
        args = ["sniffdog", str(ROOT.parent), "--no-llm", "--json", "--exclude", "demo-repos"]
        with patch("sys.argv", args), patch.dict("os.environ", {"MONGODB_URI": "", "SENTRY_DSN": ""}), \
                redirect_stdout(output):
            status = main()
        result = json.loads(output.getvalue())
        findings = result["findings"]
        self.assertEqual(status, {"safe": 0, "caution": 1, "danger": 2}[result["verdict"]["verdict"]])
        self.assertFalse(any(item["file"].startswith("demo-repos/") for item in findings))

    def test_kilo_directory_is_scanned_unless_excluded(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            hidden = root / ".kilo"
            hidden.mkdir()
            (hidden / "package.json").write_text(
                '{"scripts": {"postinstall": "curl https://example.com/setup.sh"}}')

            def scan(*options):
                output = StringIO()
                args = ["sniffdog", str(root), "--no-llm", "--json", *options]
                with patch("sys.argv", args), \
                        patch.dict("os.environ", {"MONGODB_URI": "", "SENTRY_DSN": ""}), \
                        redirect_stdout(output):
                    status = main()
                return status, json.loads(output.getvalue())["findings"]

            status, findings = scan()
            self.assertEqual(status, 2)
            self.assertTrue(any(item["rule"] == "package-script" and
                                item["file"] == ".kilo/package.json" for item in findings))
            self.assertEqual(scan("--exclude", ".kilo"), (0, []))

    def test_next_steps_match_verdict(self):
        medium = Finding("remote-dependency", "medium", "package.json", 1, "example", "Review source.")
        high = Finding("package-script", "high", "package.json", 2, "curl example", "Runs on install.")
        caution_steps = [
            "Open the cited files and check what they run before installing.",
            "Prefer running it in a separate VM or container without saved passwords or keys.",
            "Verify the recruiter on the company's official site.",
        ]
        self.assertEqual(fallback([medium])["next_steps"], caution_steps)
        self.assertEqual(fallback([])["next_steps"], [
            "Verify the recruiter on the company's official site before running the project.",
            "Review the repository and its dependencies yourself.",
        ])
        self.assertEqual(fallback([high])["next_steps"], [
            "Do not run npm install or open this folder in VS Code yet.",
            "If you must investigate, use a throwaway VM with no secrets and no network.",
            "Verify the recruiter on the company's official site. If suspicious activity "
            "is confirmed, report the account to LinkedIn, GitHub, or the job board.",
        ])
        for lang in ("en", "hinglish"):
            for findings in ([], [medium]):
                self.assertNotIn("report", " ".join(fallback(findings, lang)["next_steps"]).lower())
            self.assertIn("report", " ".join(fallback([high], lang)["next_steps"]).lower())

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
            self.assertIsNone(search(None, None))
            self.assertFalse(search("Microsoft", None)["available"])

        warnings = {"organic_results": [
            {"title": f"Report Fraud - Microsoft {number}",
             "link": f"https://example.com/report-{number}", "snippet": "Microsoft scam warning"}
            for number in range(4)]}
        plain = {"organic_results": [{"title": "Test Person biography",
                                      "link": "https://example.com/bio", "snippet": "Recruiter profile"}]}
        responses = [BytesIO(json.dumps(warnings).encode()), URLError("private query text"),
                     BytesIO(json.dumps(plain).encode())]
        with patch.dict("os.environ", {"SERPAPI_API_KEY": "test", "MONGODB_URI": "",
                                    "SENTRY_DSN": ""}), \
                patch("sniffdog.recruiter.urlopen", side_effect=responses) as fetch:
            verdict, findings, used_llm, github, check, notes, tracing = scan_target(
                str(ROOT / "safe-assignment"), True, "en", "Microsoft", "Test Person")
        self.assertEqual(verdict["verdict"], "safe")
        self.assertEqual(findings, [])
        self.assertEqual(check["failed"], 1)
        self.assertEqual(check["total"], 3)
        self.assertEqual(len(check["names"][0]["reports"]), 4)
        self.assertTrue(all(call.kwargs["timeout"] == 30 for call in fetch.call_args_list))
        output = render("safe", verdict, findings, used_llm, github, notes, check, tracing)
        self.assertIn("Recruiter check (web):", output)
        self.assertIn("Scammers have impersonated Microsoft before (4 reports).", output)
        self.assertIn("No scam reports found for Test Person.", output)
        self.assertIn("1 of 3 searches failed.", output)
        self.assertIn("https://example.com/report-2", output)
        self.assertNotIn("https://example.com/report-3", output)
        self.assertNotIn("private query text", output)

        with patch.dict("os.environ", {"SERPAPI_API_KEY": "test"}), \
                patch("sniffdog.recruiter.urlopen", side_effect=[BytesIO(b"{}"), BytesIO(b"{}")]):
            clear = search("Microsoft", None)
        self.assertEqual(clear["failed"], 0)
        self.assertEqual(clear["names"][0]["reports"], [])
        self.assertIn("No scam reports found for Microsoft. That's not proof the recruiter is real.",
                      render("safe", verdict, findings, used_llm, github, notes, clear, tracing))

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
                 "start_timestamp": "start", "timestamp": "end", "platform": "python",
                 "prompt": "private code", "message": "finding text",
                 "breadcrumbs": [{"message": "finding text"}],
                 "request": {"data": "private code"},
                 "tags": {"query": "db.find({'secret': 'private code'})"},
                 "contexts": {"trace": {"trace_id": "id", "span_id": "parent",
                                         "status": "ok", "secret": "private code"},
                              "mongodb": {"query": "db.find({'secret': 'private code'})"}},
                 "spans": [{"op": "scripts", "description": "scripts", "span_id": "child",
                            "trace_id": "id", "start_timestamp": "start", "timestamp": "end",
                            "tags": {"prompt": "private code"},
                            "data": {"findings": 2, "prompt": "private code",
                                     "query": "db.find({'secret': 'private code'})"}}]}
        clean = before_send_transaction(event, {})
        self.assertIsNotNone(clean)
        self.assertEqual(clean["type"], "transaction")
        self.assertEqual(clean["transaction"], "scan")
        self.assertEqual(clean["contexts"]["trace"],
                         {"trace_id": "id", "span_id": "parent", "status": "ok"})
        self.assertEqual({key: clean["spans"][0][key] for key in
                          ("op", "description", "start_timestamp", "timestamp")},
                         {"op": "scripts", "description": "scripts",
                          "start_timestamp": "start", "timestamp": "end"})
        self.assertEqual(clean["spans"][0]["data"], {"findings": 2})
        for secret in ("private code", "finding text", "db.find"):
            self.assertNotIn(secret, json.dumps(clean))

    def test_tracing_debug_and_flush_on_cli_exit(self):
        from sniffdog import tracing

        sdk = SimpleNamespace(init=Mock(), flush=Mock())
        with patch.dict("sys.modules", {"sentry_sdk": sdk}), \
                patch.dict("os.environ", {"SENTRY_DSN": "https://key@example.com/1",
                                          "SENTRY_DEBUG": "1"}), \
                patch.object(tracing, "_sdk", None):
            self.assertTrue(tracing.configure())
            self.assertTrue(sdk.init.call_args.kwargs["debug"])
            self.assertFalse(sdk.init.call_args.kwargs["default_integrations"])
            self.assertFalse(sdk.init.call_args.kwargs["auto_enabling_integrations"])
            tracing.flush()
            sdk.flush.assert_called_once_with(timeout=5)

        with tempfile.TemporaryDirectory() as directory, \
                patch("sniffdog.cli.flush") as flush, \
                patch.dict("os.environ", {"SENTRY_DSN": "", "MONGODB_URI": ""}):
            output = StringIO()
            with patch("sys.argv", ["sniffdog", directory, "--no-llm"]), redirect_stdout(output):
                self.assertEqual(main(), 0)
            with patch("sys.argv", ["sniffdog", str(Path(directory) / "missing"), "--no-llm"]), \
                    redirect_stderr(output):
                self.assertEqual(main(), 3)
            self.assertEqual(flush.call_count, 2)
