"""Find suspicious JavaScript and TypeScript signals."""

from pathlib import Path
import re

from sniffdog.common import Finding, entropy, iter_files, line_of, read_text, rel, short


CODE = {".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx"}
NAMES = re.compile(r"\b_0x[0-9a-f]{4,}\b", re.I)
BASE64 = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{200,}={0,2}")
ESCAPES = re.compile(r"(?:\\x[0-9a-fA-F]{2}){40,}")
EVALUATION = re.compile(r"\beval\s*\(|\bnew\s+Function\s*\(")
DECODER = re.compile(r"\batob\s*\(|\bfromCharCode\s*\(|\bBuffer\.from\s*\([^\n]*?[\"']base64[\"']")
PROCESS = re.compile(r"\bchild_process\b|\bexecSync\s*\(|\bspawn\s*\(")
IP_URL = re.compile(r"https?://(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?(?:/|\b)")
HIDDEN = re.compile(r"[ \t]{150,}(\S[^\n]*)")


def scan(root: Path, excludes: tuple[Path, ...] = ()) -> list[Finding]:
    findings = []
    for path in iter_files(root, excludes):
        if path.suffix.lower() not in CODE:
            continue
        text = read_text(path)
        if text is None:
            continue
        file = rel(root, path)
        def add(rule: str, severity: str, match: re.Match, message: str, evidence: str | None = None) -> None:
            findings.append(Finding(rule, severity, file, line_of(text, match.start()),
                                    short(evidence if evidence is not None else match.group()), message))

        names = list(NAMES.finditer(text))
        if len(names) >= 5:
            add("obfuscated-names", "high" if len(names) >= 20 else "medium", names[0],
                f"This file uses {len(names)} obfuscated-style names.", f"{len(names)} names such as {names[0].group()}")
        encoded = next((m for m in BASE64.finditer(text) if entropy(m.group()) > 4.5), None)
        escapes = ESCAPES.search(text)
        if encoded or escapes:
            match = encoded or escapes
            severity = "high" if EVALUATION.search(text) or DECODER.search(text) else "medium"
            add("encoded-code", severity, match, "This file contains a long encoded string or escape sequence.")
        evaluation = EVALUATION.search(text)
        if evaluation:
            add("dynamic-evaluation", "low" if path.name.endswith(".min.js") else "medium", evaluation,
                "This file can evaluate text as code.")
        process = PROCESS.search(text)
        if process:
            add("process-execution", "medium", process, "This file can start a shell command or child process.")
        ip_url = IP_URL.search(text)
        if ip_url:
            add("raw-ip-url", "high", ip_url, "This file contacts a URL using a raw IP address.")
        hidden = HIDDEN.search(text)
        if hidden:
            add("hidden-code", "high", hidden, "Code appears after a large span of whitespace.", hidden.group(1))
        if not path.name.endswith(".min.js"):
            for line_number, line in enumerate(text.splitlines(), 1):
                if len(line) > 5000:
                    findings.append(Finding("long-line", "medium", file, line_number, short(line),
                                            "This file has a line longer than 5,000 characters."))
                    break
    return findings
