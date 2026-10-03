"""Render the result of a repository scan."""

import sys

from sniffdog.common import Finding


BADGES = {"safe": "🟢 SAFE", "caution": "🟡 CAUTION", "danger": "🔴 DANGER"}
COLORS = {"safe": "\033[32m", "caution": "\033[33m", "danger": "\033[31m"}


def render(target: str, verdict: dict, findings: list[Finding], used_llm: bool,
           github: dict | None = None, memory_notes: list[str] | None = None) -> str:
    level = verdict["verdict"]
    badge = BADGES[level]
    if sys.stdout.isatty():
        badge = f"{COLORS[level]}{badge}\033[0m"
    lines = [f"Target: {target}", badge, "", verdict["summary"], "", "Reasons:"]
    lines.extend(f"  - {reason}" for reason in verdict["reasons"])
    lines.append("Next steps:")
    lines.extend(f"  - {step}" for step in verdict["next_steps"])
    lines.append(f"Findings ({len(findings)}):")
    for finding in findings:
        location = f"{finding.file}:{finding.line}" if finding.line else finding.file
        lines.append(f"  - [{finding.severity}] {finding.rule} at {location}: {finding.message}")
        lines.append(f"    Evidence: {finding.evidence}")
    if github:
        lines.append("GitHub facts:")
        lines.extend(f"  {key}: {value}" for key, value in github.items())
    lines.append("Memory:")
    if memory_notes:
        lines.extend(f"  - {note}" for note in memory_notes)
    else:
        lines.append("  off")
    lines.append(f"Explainer: {'Gemma (local)' if used_llm else 'built-in rules'}")
    lines.append("Static checks only — nothing from the repo was executed. Not a guarantee.")
    return "\n".join(lines)
