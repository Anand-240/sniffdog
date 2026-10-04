"""Keep rule severity authoritative while explaining findings locally."""

import json
import os
import re
from copy import deepcopy
from difflib import SequenceMatcher
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from sniffdog.common import Finding
from sniffdog.tracing import count


SCHEMA = {
    "type": "object",
    "properties": {
        "verdict": {"type": "string", "enum": ["safe", "caution", "danger"]},
        "summary": {"type": "string"},
        "what_this_means": {"type": "array", "items": {"type": "object", "properties": {
            "rule": {"type": "string"}, "file_line": {"type": "string"},
            "explanation": {"type": "string", "maxLength": 300}},
            "required": ["rule", "file_line", "explanation"]}},
    },
    "required": ["verdict", "summary", "what_this_means"],
    "additionalProperties": False,
}
CONTACT_RECRUITER = re.compile(
    r"\b(?:report|contact|message|notify|tell|send|reply)\b[^.!?\n]{0,80}\bto\s+"
    r"(?:(?:the|your|a)\s+)?recruiter\b|"
    r"\b(?:contact|message|notify|tell)\s+(?:(?:the|your|a)\s+)?recruiter\b", re.I)
ALREADY_HAPPENED = re.compile(
    r"\b(?:has|have|had|was|were|is|are|has been|have been)\s+(?:already\s+)?"
    r"(?:infected|compromised|stealing|exfiltrating|stolen|executed)\b|"
    r"\byour\s+(?:machine|computer|system)\s+(?:is|was|has been)\s+"
    r"(?:infected|compromised)\b", re.I)


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
                        "explanation": explanation, "source": "rule"})
        if len(bullets) == 5:
            break
    return bullets


def fallback(findings: list[Finding], lang: str = "en") -> dict:
    level = rule_verdict(findings)
    if lang == "hinglish":
        if level == "safe":
            return {"verdict": level,
                    "summary": "Static checks mein koi known red flag nahi mila. Safety ki guarantee nahi hai.",
                    "what_this_means": [],
                    "next_steps": ["Project chalane se pehle recruiter ko official site par verify karo.",
                                   "Repo aur dependencies khud bhi review karo."]}
        return {"verdict": level,
                "summary": f"Static checks mein {len(findings)} suspicious signals mile. Files pehle review karo.",
                "what_this_means": finding_bullets(findings, lang),
                "next_steps": ["Abhi npm install mat chalao aur folder VS Code mein mat kholo.",
                               "Zaroori ho to bina secrets aur network wali throwaway VM mein dekho.",
                               "Recruiter ko official site par verify karo. Suspicious activity confirm ho to "
                               "account LinkedIn, GitHub, ya job board par report karo."]}
    if level == "safe":
        return {"verdict": level,
                "summary": "No known red flags were found by static checks. This is not a guarantee of safety.",
                "what_this_means": [],
                "next_steps": ["Verify the recruiter on the company's official site before running the project.",
                               "Review the repository and its dependencies yourself."]}
    return {"verdict": level,
            "summary": (f"Static checks found {len(findings)} suspicious signal(s) in this repository. "
                        "Review the cited files before running anything."),
            "what_this_means": finding_bullets(findings, lang),
            "next_steps": ["Do not run npm install or open this folder in VS Code yet.",
                           "If you must investigate, use a throwaway VM with no secrets and no network.",
                           "Verify the recruiter on the company's official site. If suspicious activity "
                           "is confirmed, report the account to LinkedIn, GitHub, or the job board."]}


def meaning_matches(finding: Finding, explanation: str) -> bool:
    ignored = {"this", "that", "file", "code", "with", "from", "into", "could"}
    source = {word for word in re.findall(r"[a-z]{4,}", finding.message.lower()) if word not in ignored}
    words = set(re.findall(r"[a-z]{4,}", explanation.lower()))
    effect = explanation.split(",", 1)[-1]
    action = re.search(r"\b(?:run|start|execut\w*|download|fetch|install|load|read|come|find|connect\w*|"
                       r"evaluat(?:e|es|ed|ing)|send|contact|replace|pull)\b", effect, re.I)
    return bool(source & words) and bool(action)


def valid_sentence(value: str, rule_message: str = "") -> bool:
    if not value or len(value) > 300 or CONTACT_RECRUITER.search(value) or ALREADY_HAPPENED.search(value):
        return False
    sentence = value.strip().lstrip("\"'“”‘’ ")
    if not re.match(r"^(?:If you|When you|As soon as you|Once you|Opening|Running)\b", sentence, re.I):
        return False
    normalized = re.sub(r"[^\w\s]", "", sentence.lower())
    rule_normalized = re.sub(r"[^\w\s]", "", rule_message.lower())
    if rule_message and SequenceMatcher(None, normalized, rule_normalized).ratio() > 0.6:
        return False
    return len(re.split(r"(?<=[.!?])\s+", sentence)) == 1


def opening_for(rule: str) -> str:
    if rule in {"npm-registry", "package-script", "remote-dependency", "typosquat"}:
        return "When you run npm install"
    if rule == "vscode-folder-open":
        return "As soon as you open this folder in VS Code"
    return "If you run this project"


def explain(findings: list[Finding], context: dict, lang: str = "en") -> tuple[dict, bool]:
    result = fallback(findings, lang)
    selected = [item for item in findings if item.line is not None][:5]
    if not selected:
        return result, False
    language = "Use Hinglish in Roman script." if lang == "hinglish" else "Use plain English."
    system = ("For each finding, write ONE plain sentence about the consequence on the user's "
              "machine if they run or open the project. Begin with 'If you', 'When you', "
              "'As soon as you', 'Once you', 'Opening', or 'Running'. Explain the effect, "
              "not the rule wording. Copy rule and "
              "file_line exactly; return one what_this_means object per finding, in order. "
              + language + " Nothing was executed. Never claim the user's machine is infected "
              "or compromised. Only describe what the files would do if run. Never tell the "
              "user to contact the recruiter. Describe the direct action; do not invent "
              "a security scan or a pause. Examples of explanation text:\n"
              "package-script → 'When you run npm install, this script starts by itself and "
              "could download something onto your machine.'\n"
              "vscode-folder-open → 'As soon as you open this folder in VS Code, the task "
              "could run commands on your machine without another click.'\n"
              "npm-registry → 'When you run npm install, packages come from an unknown server "
              "instead of the official npm registry, so any of them could be replaced with malware.'")
    brief = [{"file_line": f"{item.file}:{item.line}", "rule": item.rule,
              "message": item.message} for item in selected]
    schema = deepcopy(SCHEMA)
    schema["properties"]["what_this_means"]["minItems"] = len(selected)
    schema["properties"]["what_this_means"]["maxItems"] = len(selected)
    payload = {"model": os.getenv("OLLAMA_MODEL", "gemma3:1b"), "stream": False,
               "format": schema, "options": {"temperature": 0, "num_ctx": 4096},
               "messages": [{"role": "system", "content": system},
                            {"role": "user", "content": json.dumps({"findings": brief, "context": context})}]}
    host = os.getenv("OLLAMA_HOST", "http://localhost:11434").rstrip("/")
    try:
        parsed = urlparse(host)
    except ValueError:
        return result, False
    if parsed.scheme != "http" or parsed.hostname not in {"localhost", "127.0.0.1", "::1"}:
        return result, False
    best = {}
    best_summary = None
    reason = "invalid response"
    for attempt in range(2):
        if attempt:
            payload["messages"].append({"role": "system", "content":
                                        "Retry: begin each sentence with If you, When you, As soon as you, "
                                        "Once you, Opening, or Running. "
                                        "Describe a consequence on the user's machine, not the rule message. "
                                        "Copy each rule and file_line exactly. Nothing has happened yet."})
        request = Request(f"{host}/api/chat", data=json.dumps(payload).encode(),
                          headers={"Content-Type": "application/json"}, method="POST")
        try:
            with urlopen(request, timeout=60) as response:
                raw = json.load(response)
            count("eval_count", raw.get("eval_count", 0))
            answer = json.loads(raw["message"]["content"])
        except (HTTPError, URLError, TimeoutError, OSError):
            break
        except (ValueError, KeyError, TypeError):
            reason = "invalid JSON response"
            continue
        if not isinstance(answer, dict) or not isinstance(answer.get("what_this_means"), list):
            reason = "missing explanation list"
            continue
        text_parts = [answer.get("summary", "")]
        text_parts.extend(item.get("explanation", "") for item in answer["what_this_means"]
                          if isinstance(item, dict))
        text_parts.extend(answer.get("next_steps", []) if isinstance(answer.get("next_steps"), list) else [])
        if CONTACT_RECRUITER.search(" ".join(part for part in text_parts if isinstance(part, str))):
            reason = "answer advised contacting the recruiter"
            continue
        summary = answer.get("summary")
        if isinstance(summary, str):
            sentences = re.split(r"(?<=[.!?])\s+", summary.strip())
            if (len(sentences) == 2 and len(summary) <= 350
                    and not CONTACT_RECRUITER.search(summary)
                    and not ALREADY_HAPPENED.search(summary)):
                best_summary = summary
        for finding in selected:
            location = f"{finding.file}:{finding.line}"
            key = (location, finding.rule)
            if key in best:
                continue
            for item in answer["what_this_means"]:
                if (not isinstance(item, dict) or item.get("file_line") != location
                        or item.get("rule") != finding.rule
                        or not isinstance(item.get("explanation"), str)):
                    continue
                sentence = item["explanation"].strip()
                if valid_sentence(sentence, finding.message) and meaning_matches(finding, sentence):
                    best[key] = {"rule": finding.rule, "file_line": location,
                                 "explanation": sentence, "source": "Gemma"}
                    break
        if len(best) >= min(3, len(selected)):
            break
        reason = f"only {len(best)} of {len(selected)} sentences passed validation"
    if len(best) < min(3, len(selected)) and reason != "answer advised contacting the recruiter":
        focused_schema = {"type": "object", "properties": {"explanation": {
            "type": "string", "maxLength": 300}},
            "required": ["explanation"], "additionalProperties": False}
        for finding in selected:
            location = f"{finding.file}:{finding.line}"
            if (location, finding.rule) in best:
                continue
            opening = opening_for(finding.rule)
            focused = {"model": payload["model"], "stream": False, "format": focused_schema,
                       "options": {"temperature": 0, "num_ctx": 4096},
                       "messages": [{"role": "system", "content":
                                     "Write one sentence about the consequence on the user's machine. "
                                     "Nothing was executed. Never claim infection or compromise. "
                                     "Do not copy the rule message or invent unrelated actions. " + language},
                                    {"role": "user", "content":
                                     f"{location} {finding.rule}: {finding.message}\n"
                                     f"Begin exactly with '{opening},' and explain what could happen "
                                     "on the user's machine. Write one sentence only."}]}
            request = Request(f"{host}/api/chat", data=json.dumps(focused).encode(),
                              headers={"Content-Type": "application/json"}, method="POST")
            try:
                with urlopen(request, timeout=60) as response:
                    raw = json.load(response)
                count("eval_count", raw.get("eval_count", 0))
                sentence = json.loads(raw["message"]["content"])["explanation"].strip()
            except (HTTPError, URLError, TimeoutError, OSError, ValueError, KeyError, TypeError):
                continue
            if valid_sentence(sentence, finding.message) and meaning_matches(finding, sentence):
                best[(location, finding.rule)] = {"rule": finding.rule, "file_line": location,
                                                  "explanation": sentence, "source": "Gemma"}
        reason = f"only {len(best)} of {len(selected)} sentences passed validation"
    result["what_this_means"] = [best.get((item["file_line"], item["rule"]), item)
                                 for item in result["what_this_means"]]
    if best_summary:
        result["summary"] = best_summary
    used_llm = len(best) >= min(3, len(selected))
    result["gemma_passed"] = len(best)
    result["gemma_total"] = len(selected)
    if not best:
        result["discard_reason"] = reason
    return result, used_llm
