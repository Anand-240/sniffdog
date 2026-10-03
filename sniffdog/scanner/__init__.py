"""Run the repository's static checks."""

from pathlib import Path

from sniffdog.common import Finding, RANK
from sniffdog.scanner import deps, disguised, obfuscation, scripts, vscode


def run_all(root: Path) -> list[Finding]:
    findings = []
    for scanner in (scripts, vscode, obfuscation, disguised, deps):
        findings.extend(scanner.scan(root))
    return sorted(findings, key=lambda item: (-RANK[item.severity], item.file, item.line or 0, item.rule))
