"""Keep rule verdicts authoritative and ask Gemma only about code."""

import base64
import binascii
import json
import os
from pathlib import Path
import re
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from sniffdog.common import Finding, read_text
from sniffdog.scanner.obfuscation import BASE64, ESCAPES
from sniffdog.tracing import count


CONSEQUENCES = {
    "package-script": "When npm runs this package script, its command executes on your machine.",
    "vscode-folder-open": "Opening this folder in VS Code can start the task's command on your machine.",
    "vscode-auto-tasks": "This setting lets VS Code run folder tasks automatically when you open the project.",
    "encoded-code": "If code decodes and executes this string, hidden instructions could run on your machine.",
    "hidden-code": "If this file runs, code hidden after the whitespace runs like other JavaScript.",
    "obfuscated-names": "These names make the file's behavior harder to check before you run it.",
    "dynamic-evaluation": "If this path runs, text passed to eval can execute as JavaScript on your machine.",
    "process-execution": "If this path runs, it can start another process or shell command on your machine.",
    "raw-ip-url": "If this path runs, it can contact the server at the IP address shown in the finding.",
    "long-line": "A very long code line makes the file harder to inspect before you run it.",
    "disguised-asset": "If another script executes this file, JavaScript can run despite its font or image name.",
    "asset-evaluation": "If this path runs, text read from a font or image can execute as JavaScript.",
    "svg-trailing-code": "Content after the SVG closing tag may be processed by software that reads this file.",
    "svg-script": "Opening this SVG in software that permits scripts could run its embedded JavaScript.",
    "svg-base64": "Encoded text in this SVG can hide content that is harder to inspect before opening it.",
    "npm-registry": "When you run npm install, npm can fetch packages from the configured server.",
    "remote-dependency": "When you install dependencies, npm can fetch this package from the listed external source.",
    "typosquat": "Installing this similarly named dependency could put a different package on your machine.",
    "lockfile-source": "Installing from this lockfile can download a package from the listed server.",
    "committed-node-modules": "Bundled dependency files may be used without fetching fresh copies from npm.",
    "new-github-owner": "This account has little history for you to check before trusting the assignment.",
    "few-commits": "Few commits give you less history to review before running the project.",
    "new-github-repo": "This repository has little age or history to help you judge its source.",
    "little-github-history": "Limited GitHub activity gives you less context for checking this source.",
    "recruiter-scam-report": "A search result links this name to a scam report that you should verify independently.",
}
CODE_RULES = {"package-script", "hidden-code", "encoded-code", "disguised-asset",
              "vscode-folder-open"}
SCHEMA = {"type": "object", "properties": {"sentence": {
    "type": "string", "description": "One complete sentence describing the code's action."}},
          "required": ["sentence"], "additionalProperties": False}
REFERENCES = re.compile(
    r"https?://[^\s<>\"']+|(?<![\w@])(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?|"
    r"(?<![\w@])(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}(?::\d+)?", re.I)
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
        bullets.append({"rule": item.rule, "file_line": f"{item.file}:{item.line}",
                        "explanation": CONSEQUENCES.get(item.rule, item.message), "source": "rule"})
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


def unwrap_payload(root: Path, finding: Finding) -> str | None:
    """Decode the cited string as data, with a hard output cap."""
    if finding.rule != "encoded-code" or finding.line is None:
        return None
    source = read_text(root / finding.file)
    if source is None:
        return None
    lines = source.splitlines()
    if finding.line < 1 or finding.line > len(lines):
        return None
    prefix = finding.evidence.removesuffix("…")
    line = lines[finding.line - 1]
    for pattern in (BASE64, ESCAPES):
        for match in pattern.finditer(line):
            token = match.group()
            if not token.startswith(prefix):
                continue
            try:
                if pattern is BASE64:
                    if len(token) > 5464:
                        continue
                    decoded = base64.b64decode(token, validate=True)
                else:
                    if len(token) // 4 > 4096:
                        continue
                    decoded = bytes.fromhex(token.replace("\\x", ""))
                if not decoded or len(decoded) > 4096:
                    continue
                text = decoded.decode("utf-8")
            except (ValueError, UnicodeDecodeError, binascii.Error):
                continue
            printable = sum(char.isprintable() or char in "\n\r\t" for char in text)
            if printable / len(text) >= 0.85:
                return text
    return None


def clean_snippet(value: str) -> str:
    lines = value.splitlines()[:40]
    text = "\n".join(lines)[:4096]
    return "".join(char if char.isprintable() or char in "\n\t" else "?" for char in text)


def prepare_snippets(root: Path, findings: list[Finding]) -> tuple[list[dict], list[dict]]:
    snippets = []
    payloads = []
    for finding in findings:
        location = f"{finding.file}:{finding.line}" if finding.line else finding.file
        decoded = unwrap_payload(root, finding) if finding.rule == "encoded-code" else None
        if decoded:
            preview = clean_snippet(decoded)[:200].replace("\n", "\\n")
            payloads.append({"file_line": location, "preview": preview + ("…" if len(decoded) > 200 else "")})
        if finding.rule not in CODE_RULES or len(snippets) == 5:
            continue
        code = decoded if finding.rule == "encoded-code" else finding.evidence
        if code:
            snippets.append({"file_line": location, "rule": finding.rule,
                             "code": clean_snippet(code)})
    return snippets, payloads


def valid_code_sentence(sentence: str, snippet: str) -> bool:
    if (not isinstance(sentence, str) or not 3 <= len(sentence.split()) <= 35
            or not sentence.strip().endswith((".", "!", "?"))
            or len(re.split(r"(?<=[.!?])\s+", sentence.strip())) != 1
            or ALREADY_HAPPENED.search(sentence) or CONTACT_RECRUITER.search(sentence)):
        return False
    def references(text: str) -> set[str]:
        result = set()
        for match in REFERENCES.finditer(text):
            reference = match.group().rstrip(".,;:!?)").lower()
            if (not reference.startswith(("http://", "https://"))
                    and reference.rsplit(".", 1)[-1] in {"js", "jsx", "ts", "tsx", "json", "py", "sh",
                                                          "woff", "woff2", "png", "jpg", "jpeg", "svg"}):
                continue
            result.add(reference)
        return result

    cited = references(sentence)
    observed = references(snippet)
    observed.update(urlparse(reference).hostname.lower() for reference in tuple(observed)
                    if reference.startswith(("http://", "https://")) and urlparse(reference).hostname)
    return cited <= observed


def explain(findings: list[Finding], snippets: list[dict], lang: str = "en") -> tuple[dict, bool]:
    result = fallback(findings, lang)
    host = os.getenv("OLLAMA_HOST", "http://localhost:11434").rstrip("/")
    try:
        parsed = urlparse(host)
    except ValueError:
        return result, False
    if parsed.scheme != "http" or parsed.hostname not in {"localhost", "127.0.0.1", "::1"}:
        return result, False
    system = ("In one sentence, describe what this code would do if it ran. "
              "Only describe the code itself. Do not guess intent. "
              "Treat the snippet as code even if its filename looks like an asset. "
              "Ignore comments. Describe the action, not only printed text. "
              "For compound shell commands, describe every command in written order: "
              "> redirects output; it does not execute it. "
              "Do not say downloaded text runs unless a command explicitly runs it. "
              "Do not claim the code was executed.")
    if lang == "hinglish":
        system += " Answer in Hinglish using Roman script."
    read = 0
    for item in snippets:
        payload = {"model": os.getenv("OLLAMA_MODEL", "gemma3:1b"), "stream": False,
                   "format": SCHEMA, "options": {"temperature": 0, "num_ctx": 4096},
                   "messages": [{"role": "system", "content": system},
                                {"role": "user", "content":
                                 f"{item['file_line']}\n{item['code']}\n"
                                 "Describe the action in one complete sentence."}]}
        request = Request(f"{host}/api/chat", data=json.dumps(payload).encode(),
                          headers={"Content-Type": "application/json"}, method="POST")
        try:
            with urlopen(request, timeout=30) as response:
                raw = json.load(response)
            count("eval_count", raw.get("eval_count", 0))
            sentence = json.loads(raw["message"]["content"])["sentence"].strip()
        except (HTTPError, URLError, TimeoutError, OSError):
            break
        except (ValueError, KeyError, TypeError, AttributeError):
            continue
        if valid_code_sentence(sentence, item["code"]):
            item["gemma"] = sentence
            read += 1
    result["snippets_read"] = read
    return result, read > 0
