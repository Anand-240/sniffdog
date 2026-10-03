"""Run static checks from the command line."""

import argparse
import json
from pathlib import Path
import subprocess
import sys
import tempfile

from sniffdog.clone import safe_clone
from sniffdog.common import Finding, RANK
from sniffdog.github_info import inspect
from sniffdog.memory import connect, notes, save, seed
from sniffdog.recruiter import search
from sniffdog.report import render
from sniffdog.scanner import run_all
from sniffdog.tracing import configure, count, span, transaction
from sniffdog.verdict import explain, fallback


def scan_target(target: str, no_llm: bool, lang: str, company: str | None,
                recruiter: str | None) -> tuple[dict, list[Finding], bool, dict, str | None,
                                                list[str] | None, bool]:
    tracing_on = configure()
    remote = target.startswith("https://")
    commit = ""
    with transaction():
        if remote:
            with tempfile.TemporaryDirectory(prefix="sniffdog-") as directory:
                root = Path(directory) / "repo"
                with span("clone"):
                    safe_clone(target, root)
                    commit = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"],
                                            check=True, capture_output=True, text=True).stdout.strip()
                findings = run_all(root)
        else:
            root = Path(target).expanduser()
            if not root.is_dir():
                raise FileNotFoundError(f"Repository folder does not exist: {target}")
            findings = run_all(root)
        with span("github"):
            github, github_findings = inspect(target) if remote else ({}, [])
            count("findings", len(github_findings))
        with span("recruiter"):
            search_results, recruiter_findings, search_error = search(company, recruiter)
            count("findings", len(recruiter_findings))
        findings.extend(github_findings)
        findings.extend(recruiter_findings)
        findings.sort(key=lambda item: (-RANK[item.severity], item.file, item.line or 0, item.rule))
        memory_notes = None
        with span("memory"):
            client = connect()
            if client is not None:
                memory_notes = notes(client, target if remote else None, findings)
                count("matches", len(memory_notes) if memory_notes is not None else 0)
                if memory_notes is None:
                    client.close()
                    client = None
        context = {"company": company, "recruiter": recruiter, "github": github,
                   "recruiter_search": search_results, "memory_notes": memory_notes or []}
        with span("llm"):
            verdict, used_llm = (fallback(findings, lang), False) if no_llm else explain(findings, context, lang)
        if client is not None:
            if remote:
                with span("memory"):
                    stored = save(client, target, commit, verdict["verdict"], findings)
                    count("saved", int(stored))
                if not stored:
                    memory_notes = None
            client.close()
    return verdict, findings, used_llm, github, search_error, memory_notes, tracing_on


def main() -> int:
    parser = argparse.ArgumentParser(prog="sniffdog", description="Read-only checks for coding assignments")
    parser.add_argument("target", help="repository URL or local folder")
    parser.add_argument("--company")
    parser.add_argument("--recruiter")
    parser.add_argument("--lang", choices=("en", "hinglish"), default="en")
    parser.add_argument("--no-llm", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    if args.target == "seed":
        total = seed()
        print(f"Seeded {total} known patterns." if total is not None else "memory: off")
        return 0 if total is not None else 1
    try:
        verdict, findings, used_llm, github, search_error, memory_notes, tracing_on = scan_target(
            args.target, args.no_llm, args.lang, args.company, args.recruiter)
    except (FileNotFoundError, ValueError, subprocess.CalledProcessError,
            subprocess.TimeoutExpired, OSError) as error:
        print(f"Could not fetch repository: {error}", file=sys.stderr)
        return 3
    if args.json:
        print(json.dumps({"target": args.target, "verdict": verdict, "findings":
                          [finding.to_dict() for finding in findings], "used_llm": used_llm,
                          "github": github, "recruiter_search_error": search_error,
                          "memory_notes": memory_notes, "tracing_on": tracing_on}, indent=2))
    else:
        print(render(args.target, verdict, findings, used_llm, github, memory_notes,
                     search_error, tracing_on))
    return {"safe": 0, "caution": 1, "danger": 2}[verdict["verdict"]]
