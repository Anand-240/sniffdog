"""Check package scripts that can run commands."""

import json
from pathlib import Path
import re

from sniffdog.common import Finding, iter_files, line_of, read_text, rel, short


LIFECYCLE = {"preinstall", "install", "postinstall", "prepare", "preprepare", "postprepare",
             "prepublish", "prepack", "postpack"}
MANUAL = {"dev", "start", "test", "build", "serve"}
RISKY = re.compile(r"\b(?:curl|wget|eval|base64|powershell|pwsh)\b|https?://|\bnode\s+-e\b|"
                   r"\b(?:bash|sh)\s+-c\b|\|\s*(?:ba|z)?sh\b", re.I)


def scan(root: Path) -> list[Finding]:
    findings = []
    for path in iter_files(root):
        if path.name != "package.json":
            continue
        text = read_text(path)
        if text is None:
            continue
        try:
            scripts = json.loads(text).get("scripts", {})
        except (json.JSONDecodeError, AttributeError):
            continue
        if not isinstance(scripts, dict):
            continue
        for name, command in scripts.items():
            if not isinstance(command, str) or name not in LIFECYCLE | MANUAL:
                continue
            risky = bool(RISKY.search(command))
            if name in MANUAL and not risky:
                continue
            severity = "high" if name in LIFECYCLE and risky else "medium"
            match = re.search(rf'"{re.escape(name)}"\s*:', text)
            findings.append(Finding("package-script", severity, rel(root, path),
                                    line_of(text, match.start()) if match else None,
                                    short(command),
                                    f"The {name} script {'runs automatically during install or packaging' if name in LIFECYCLE else 'runs when invoked'}."))
    return findings
