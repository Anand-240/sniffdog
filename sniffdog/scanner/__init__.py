"""Run the repository's static checks."""

from pathlib import Path

from sniffdog.common import Finding, RANK
from sniffdog.scanner import deps, disguised, obfuscation, scripts, vscode
from sniffdog.tracing import count, span


def run_all(root: Path) -> list[Finding]:
    findings = []
    for scanner in (scripts, vscode, obfuscation, disguised, deps):
        with span(scanner.__name__.rsplit(".", 1)[-1]):
            found = scanner.scan(root)
            count("findings", len(found))
            findings.extend(found)
    return sorted(findings, key=lambda item: (-RANK[item.severity], item.file, item.line or 0, item.rule))
