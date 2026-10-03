"""Keep rule severity authoritative while explaining findings locally."""

import json
import os
import re
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from sniffdog.common import Finding


ORDER = {"safe": 0, "caution": 1, "danger": 2}
SCHEMA = {
    "type": "object",
    "properties": {
        "verdict": {"type": "string", "enum": ["safe", "caution", "danger"]},
        "summary": {"type": "string"},
        "reasons": {"type": "array", "items": {"type": "string"}},
        "next_steps": {"type": "array", "items": {"type": "string"}},
    },
    "required": ["verdict", "summary", "reasons", "next_steps"],
    "additionalProperties": False,
}


def rule_verdict(findings: list[Finding]) -> str:
    levels = {finding.severity for finding in findings}
    return "danger" if "high" in levels else "caution" if "medium" in levels else "safe"


def fallback(findings: list[Finding]) -> dict:
    verdict = rule_verdict(findings)
    if verdict == "safe":
        return {
            "verdict": "safe",
            "summary": "No known red flags were found by static checks. This is not a guarantee of safety.",
            "reasons": ["No scanner rule matched the files in this repository."],
            "next_steps": ["Verify the recruiter on the company's official site before running the project.",
                           "Review the repository and its dependencies yourself."],
        }
    return {
        "verdict": verdict,
        "summary": f"Static checks found {len(findings)} suspicious signal(s) in this repository.",
        "reasons": [f"{finding.file}:{finding.line or '?'}: {finding.message}" for finding in findings],
        "next_steps": ["Do not run npm install or open this folder in VS Code yet.",
                       "If you must investigate, use a throwaway VM with no secrets and no network.",
                       "Verify the recruiter on the company's official site and report the account."],
    }


def explain(findings: list[Finding], context: dict, lang: str = "en") -> tuple[dict, bool]:
    minimum = rule_verdict(findings)
    language = "Answer in Hinglish: Hindi in Latin script mixed with simple English." if lang == "hinglish" else "Answer in plain English."
    system = ("Explain static repository findings to a job-seeking fresher. " + language +
              " Write one summary sentence under 250 characters about observed signals only; "
              "put no advice in the summary. Do not claim malware, compromise, or a breach is proven. "
              " Cite file:line in reasons. Use only the given findings; do not invent risks. "
              "Your verdict must be at least as severe as the rule verdict. "
              "Give concrete next steps: do not run npm install or open the folder in VS Code yet; "
              "use a throwaway VM with no secrets and no network; verify the recruiter on the "
              "company's official site; report the account. If there are no findings, say no known "
              "red flags were found, which is not a guarantee.")
    payload = {
        "model": os.getenv("OLLAMA_MODEL", "gemma3:1b"),
        "stream": False,
        "format": SCHEMA,
        "options": {"temperature": 0.2, "num_ctx": 4096},
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": json.dumps({"minimum_verdict": minimum,
                                                   "findings": [item.to_dict() for item in findings[:25]],
                                                   "context": context})},
        ],
    }
    host = os.getenv("OLLAMA_HOST", "http://localhost:11434").rstrip("/")
    try:
        parsed = urlparse(host)
    except ValueError:
        return fallback(findings), False
    if parsed.scheme != "http" or parsed.hostname not in {"localhost", "127.0.0.1", "::1"}:
        return fallback(findings), False
    request = Request(f"{host}/api/chat", data=json.dumps(payload).encode(),
                      headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urlopen(request, timeout=60) as response:
            result = json.load(response)
        answer = json.loads(result["message"]["content"])
        if (answer.get("verdict") not in ORDER or not isinstance(answer.get("summary"), str)
                or len(answer["summary"]) > 350
                or re.search(r"\b(?:compromis\w*|breach\w*|infect\w*|malware|unauthorized|"
                             r"damag\w*|malicious|vulnerabilit\w*)\b", answer["summary"], re.I)
                or not isinstance(answer.get("reasons"), list)
                or not all(isinstance(reason, str) for reason in answer["reasons"])
                or not isinstance(answer.get("next_steps"), list)
                or not all(isinstance(step, str) for step in answer["next_steps"])):
            raise ValueError("Ollama returned an incomplete explanation")
    except (HTTPError, URLError, TimeoutError, OSError, ValueError, KeyError, TypeError):
        return fallback(findings), False
    if ORDER[answer["verdict"]] < ORDER[minimum] or (not findings and answer["verdict"] != "safe"):
        return fallback(findings), False
    rules = fallback(findings)
    if not findings:
        answer["summary"] = rules["summary"]
    answer["reasons"] = rules["reasons"]
    answer["next_steps"] = rules["next_steps"]
    return answer, True
