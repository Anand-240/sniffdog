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


def fallback(findings: list[Finding], lang: str = "en") -> dict:
    verdict = rule_verdict(findings)
    if lang == "hinglish":
        if verdict == "safe":
            return {"verdict": "safe",
                    "summary": "Static checks mein koi known red flag nahi mila. Safety ki guarantee nahi hai.",
                    "reasons": ["Is repo ki files par koi scanner rule match nahi hua."],
                    "next_steps": ["Project chalane se pehle recruiter ko company ki official site par verify karo.",
                                   "Repo aur dependencies khud bhi review karo."]}
        return {"verdict": verdict,
                "summary": f"Static checks mein is repo ke {len(findings)} suspicious signals mile.",
                "reasons": [f"{item.file}:{item.line or '?'}: Yeh signal dekho: {item.message}"
                            for item in findings],
                "next_steps": ["Abhi npm install mat chalao aur folder VS Code mein mat kholo.",
                               "Zaroori ho to bina secrets aur network wali throwaway VM mein dekho.",
                               "Recruiter ko company ki official site par verify karo aur account report karo."]}
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
    language = ("Jawab Hinglish mein do: Roman Hindi aur simple English mix karo. "
                "Summary mein 'yeh', 'hai', ya 'mat' jaise Hindi shabd zaroor likho."
                if lang == "hinglish" else "Use plain English.")
    system = ("Explain these static findings to a new job seeker. " + language +
              " Nothing was executed. Never claim the user's machine is infected or compromised. "
              "Only describe what the files would do if run. Cite file:line. Use no invented facts. "
              f"Verdict must be {minimum} or higher. Keep the summary short. "
              "For risks, advise against npm install and opening in VS Code; suggest a throwaway VM "
              "with no secrets or network, checking the recruiter on the official site, and reporting the account. "
              "With no findings, say no known red flags were found, not that the repo is guaranteed safe.")
    brief = [{"rule": item.rule, "severity": item.severity,
              "file:line": f"{item.file}:{item.line or '?'}", "message": item.message}
             for item in findings[:8]]
    payload = {
        "model": os.getenv("OLLAMA_MODEL", "gemma3:1b"),
        "stream": False,
        "format": SCHEMA,
        "options": {"temperature": 0.2, "num_ctx": 4096},
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": json.dumps({"minimum_verdict": minimum,
                                                   "findings": brief, "context": context})},
        ],
    }
    if lang == "hinglish":
        payload["messages"].append({"role": "user", "content":
                                    "Summary Roman Hindi mein 'Yeh repo...' se shuru karo. "
                                    "Simple English words bhi use karo. JSON fields sab bharo."})
    host = os.getenv("OLLAMA_HOST", "http://localhost:11434").rstrip("/")
    try:
        parsed = urlparse(host)
    except ValueError:
        return fallback(findings, lang), False
    if parsed.scheme != "http" or parsed.hostname not in {"localhost", "127.0.0.1", "::1"}:
        return fallback(findings, lang), False
    reason = "invalid response"
    for attempt in range(2):
        if attempt:
            payload["messages"].append({"role": "system", "content":
                                        f"Retry: return valid JSON with verdict {minimum} or higher. "
                                        "Describe file behavior only; nothing was executed. "
                                        + ("Summary Roman Hindi mein likho." if lang == "hinglish" else "")})
        request = Request(f"{host}/api/chat", data=json.dumps(payload).encode(),
                          headers={"Content-Type": "application/json"}, method="POST")
        try:
            with urlopen(request, timeout=60) as response:
                result = json.load(response)
            answer = json.loads(result["message"]["content"])
        except (HTTPError, URLError, TimeoutError, OSError):
            rules = fallback(findings, lang)
            if attempt:
                rules["discard_reason"] = "Ollama unavailable on retry"
            return rules, False
        except (ValueError, KeyError, TypeError):
            reason = "invalid JSON response"
            continue
        if (not isinstance(answer, dict) or not isinstance(answer.get("verdict"), str)
                or answer["verdict"] not in ORDER):
            reason = "missing or invalid verdict"
        elif ORDER[answer["verdict"]] < ORDER[minimum]:
            reason = f"model verdict {answer['verdict']} is below rule verdict {minimum}"
        elif (not isinstance(answer.get("summary"), str) or not answer["summary"].strip()
              or not isinstance(answer.get("reasons"), list)
              or not all(isinstance(value, str) for value in answer["reasons"])
              or not isinstance(answer.get("next_steps"), list)
              or not all(isinstance(value, str) for value in answer["next_steps"])):
            reason = "missing explanation fields"
        elif lang == "hinglish" and not re.search(r"\b(?:yeh|hai|hain|nahi|mat|mein|karo)\b",
                                                    answer["summary"], re.I):
            reason = "answer was not in Hinglish"
        else:
            rules = fallback(findings, lang)
            if not findings:
                answer["summary"] = rules["summary"]
            answer["reasons"] = rules["reasons"]
            answer["next_steps"] = rules["next_steps"]
            return answer, True
    rules = fallback(findings, lang)
    rules["discard_reason"] = reason
    return rules, False
