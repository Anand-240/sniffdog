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
        "what_this_means": {"type": "array", "items": {"type": "object", "properties": {
            "rule": {"type": "string"}, "file_line": {"type": "string"},
            "explanation": {"type": "string"}},
            "required": ["rule", "file_line", "explanation"]}},
        "next_steps": {"type": "array", "items": {"type": "string"}},
    },
    "required": ["verdict", "summary", "what_this_means", "next_steps"],
    "additionalProperties": False,
}
CONTACT_RECRUITER = re.compile(
    r"\b(?:report|contact|message|notify|tell|send|reply)\b[^.!?\n]{0,80}\bto\s+"
    r"(?:(?:the|your|a)\s+)?recruiter\b|"
    r"\b(?:contact|message|notify|tell)\s+(?:(?:the|your|a)\s+)?recruiter\b", re.I)
UNOBSERVED_ACTIVITY = re.compile(r"\b(?:infected|compromised)\b[^.!?\n]{0,20}"
                                  r"\b(?:machine|computer|system)\b|"
                                  r"\b(?:machine|computer|system)\s+(?:is|was)\s+"
                                  r"(?:exhibiting|showing|running|infected|compromised)\b", re.I)


def rule_verdict(findings: list[Finding]) -> str:
    levels = {finding.severity for finding in findings}
    return "danger" if "high" in levels else "caution" if "medium" in levels else "safe"


def finding_bullets(findings: list[Finding], lang: str) -> list[dict]:
    bullets = []
    for item in findings:
        if item.line is None:
            continue
        explanation = f"Yeh signal dekho: {item.message}" if lang == "hinglish" else item.message
        bullets.append({"rule": item.rule, "file_line": f"{item.file}:{item.line}",
                        "explanation": explanation})
        if len(bullets) == 5:
            break
    return bullets


def meaning_matches(finding: Finding, explanation: str) -> bool:
    ignored = {"this", "that", "file", "code", "with", "from", "into", "could"}
    source = {word for word in re.findall(r"[a-z]{4,}", finding.message.lower()) if word not in ignored}
    words = set(re.findall(r"[a-z]{4,}", explanation.lower()))
    return bool(source) and len(source & words) * 2 >= len(source)


def fallback(findings: list[Finding], lang: str = "en") -> dict:
    verdict = rule_verdict(findings)
    if lang == "hinglish":
        if verdict == "safe":
            return {"verdict": "safe",
                    "summary": "Static checks mein koi known red flag nahi mila. Safety ki guarantee nahi hai.",
                    "what_this_means": [],
                    "next_steps": ["Project chalane se pehle recruiter ko company ki official site par verify karo.",
                                   "Repo aur dependencies khud bhi review karo."]}
        return {"verdict": verdict,
                "summary": (f"Static checks mein is repo ke {len(findings)} suspicious signals mile. "
                            "In files ko chalane se pehle review karo."),
                "what_this_means": finding_bullets(findings, lang),
                "next_steps": ["Abhi npm install mat chalao aur folder VS Code mein mat kholo.",
                               "Zaroori ho to bina secrets aur network wali throwaway VM mein dekho.",
                               "Recruiter ko company ki official site par verify karo. "
                               "Agar suspicious activity confirm ho, account ko LinkedIn, GitHub, "
                               "ya job board par report karo."]}
    if verdict == "safe":
        return {
            "verdict": "safe",
            "summary": "No known red flags were found by static checks. This is not a guarantee of safety.",
            "what_this_means": [],
            "next_steps": ["Verify the recruiter on the company's official site before running the project.",
                           "Review the repository and its dependencies yourself."],
        }
    return {
        "verdict": verdict,
        "summary": (f"Static checks found {len(findings)} suspicious signal(s) in this repository. "
                    "Review the cited files before running anything."),
        "what_this_means": finding_bullets(findings, lang),
        "next_steps": ["Do not run npm install or open this folder in VS Code yet.",
                       "If you must investigate, use a throwaway VM with no secrets and no network.",
                       "Verify the recruiter on the company's official site. "
                       "If suspicious activity is confirmed, report the account to LinkedIn, "
                       "GitHub, or the job board."],
    }


def explain(findings: list[Finding], context: dict, lang: str = "en") -> tuple[dict, bool]:
    minimum = rule_verdict(findings)
    language = ("Jawab Hinglish mein do: Roman Hindi aur simple English mix karo. "
                "Summary mein 'yeh', 'hai', ya 'mat' jaise Hindi shabd zaroor likho."
                if lang == "hinglish" else "Use plain English.")
    system = ("Explain static findings to a new job seeker. " + language +
              " Nothing was executed. Never claim the user's machine is infected or compromised. "
              "Only describe what the repository files contain or would do if run. "
              "Start the summary with 'This repository'. Give exactly two short summary sentences. "
              "Give 3 to 5 plain-language what_this_means bullets, each with the exact rule and file_line "
              "of one supplied finding. Paraphrase its message; do not infer attacker intent or data theft. "
              f"Verdict must be {minimum} or higher. "
              "Do not advise running npm install or opening in VS Code. Suggest a throwaway VM "
              "without secrets or network. Verify the recruiter on the company's official site. "
              "If suspicious activity is confirmed, report the account to the platform "
              "(LinkedIn, GitHub, or the job board), never to the recruiter. "
              "With no findings, say no known red flags were found; safety is not guaranteed.")
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
                                    "Summary Roman Hindi mein 'Yeh repo' se shuru karo. "
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
                                        "Write two summary sentences and 3 to 5 bullets with exact rule and file_line. "
                                        "Report to the platform, never the recruiter. "
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
              or not isinstance(answer.get("what_this_means"), list)
              or not isinstance(answer.get("next_steps"), list)
              or not all(isinstance(value, str) for value in answer["next_steps"])):
            reason = "missing explanation fields"
        elif CONTACT_RECRUITER.search(" ".join(
                [answer["summary"], *answer["next_steps"],
                 *(item.get("explanation", "") for item in answer["what_this_means"]
                   if isinstance(item, dict) and isinstance(item.get("explanation"), str))])):
            reason = "answer advised contacting the recruiter"
        elif UNOBSERVED_ACTIVITY.search(" ".join(
                [answer["summary"], *(item.get("explanation", "") for item in answer["what_this_means"]
                                      if isinstance(item, dict) and isinstance(item.get("explanation"), str))])):
            reason = "answer described unobserved system activity"
        elif lang == "hinglish" and not re.search(r"\b(?:yeh|hai|hain|nahi|mat|mein|karo)\b",
                                                    answer["summary"], re.I):
            reason = "answer was not in Hinglish"
        else:
            sentences = re.split(r"(?<=[.!?])\s+", answer["summary"].lstrip("-• \t"))
            valid = []
            known = {(f"{item.file}:{item.line}", item.rule): item
                     for item in findings if item.line is not None}
            for item in answer["what_this_means"]:
                if (isinstance(item, dict) and isinstance(item.get("file_line"), str)
                        and isinstance(item.get("rule"), str)
                        and isinstance(item.get("explanation"), str)
                        and item["explanation"].strip()
                        and (item["file_line"], item["rule"]) in known
                        and meaning_matches(known[(item["file_line"], item["rule"])], item["explanation"])
                        and (item["file_line"], item["rule"]) not in
                        {(entry["file_line"], entry["rule"]) for entry in valid}):
                    valid.append(item)
            needed = min(3, len(known))
            if len(sentences) < 2:
                reason = "summary did not contain two sentences"
                continue
            if len(valid) < needed:
                reason = "fewer than three bullets matched findings"
                continue
            rules = fallback(findings, lang)
            if not findings:
                answer["summary"] = rules["summary"]
            else:
                answer["summary"] = " ".join(sentences[:2])
            answer["what_this_means"] = valid[:5]
            answer["next_steps"] = rules["next_steps"]
            return answer, True
    rules = fallback(findings, lang)
    rules["discard_reason"] = reason
    return rules, False
