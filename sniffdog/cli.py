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
from sniffdog.recruiter import search
from sniffdog.report import render
from sniffdog.scanner import run_all
from sniffdog.verdict import explain, fallback


def scan_target(target: str, no_llm: bool, lang: str, company: str | None,
                recruiter: str | None) -> tuple[dict, list[Finding], bool, dict, str | None]:
    if target.startswith("https://"):
        with tempfile.TemporaryDirectory(prefix="sniffdog-") as directory:
            root = Path(directory) / "repo"
            safe_clone(target, root)
            findings = run_all(root)
    else:
        root = Path(target).expanduser()
        if not root.is_dir():
            raise FileNotFoundError(f"Repository folder does not exist: {target}")
        findings = run_all(root)
    github, github_findings = inspect(target) if target.startswith("https://") else ({}, [])
    search_results, recruiter_findings, search_error = search(company, recruiter)
    findings.extend(github_findings)
    findings.extend(recruiter_findings)
    findings.sort(key=lambda item: (-RANK[item.severity], item.file, item.line or 0, item.rule))
    context = {"company": company, "recruiter": recruiter, "github": github,
               "recruiter_search": search_results}
    verdict, used_llm = (fallback(findings, lang), False) if no_llm else explain(findings, context, lang)
    return verdict, findings, used_llm, github, search_error


def main() -> int:
    parser = argparse.ArgumentParser(prog="sniffdog", description="Read-only checks for coding assignments")
    parser.add_argument("target", help="repository URL or local folder")
    parser.add_argument("--company")
    parser.add_argument("--recruiter")
    parser.add_argument("--lang", choices=("en", "hinglish"), default="en")
    parser.add_argument("--no-llm", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    try:
        verdict, findings, used_llm, github, search_error = scan_target(
            args.target, args.no_llm, args.lang, args.company, args.recruiter)
    except (FileNotFoundError, ValueError, subprocess.CalledProcessError,
            subprocess.TimeoutExpired, OSError) as error:
        print(f"Could not fetch repository: {error}", file=sys.stderr)
        return 3
    if args.json:
        print(json.dumps({"target": args.target, "verdict": verdict, "findings":
                          [finding.to_dict() for finding in findings], "used_llm": used_llm,
                          "github": github, "recruiter_search_error": search_error}, indent=2))
    else:
        print(render(args.target, verdict, findings, used_llm, github, search_error=search_error))
    return {"safe": 0, "caution": 1, "danger": 2}[verdict["verdict"]]
