"""Render the result of a repository scan."""

import sys

from sniffdog.common import Finding


BADGES = {"safe": "🟢 SAFE", "caution": "🟡 CAUTION", "danger": "🔴 DANGER"}
COLORS = {"safe": "\033[32m", "caution": "\033[33m", "danger": "\033[31m"}


def render(target: str, verdict: dict, findings: list[Finding], used_llm: bool,
           github: dict | None = None, memory_notes: list[str] | None = None,
           recruiter_check: dict | None = None, tracing_on: bool = False) -> str:
    level = verdict["verdict"]
    badge = BADGES[level]
    if sys.stdout.isatty():
        badge = f"{COLORS[level]}{badge}\033[0m"
    lines = [f"Target: {target}", badge, "", verdict["summary"], "", "What this means:"]
    bullets = verdict["what_this_means"]
    if bullets:
        lines.extend(f"  - {item['file_line']} ({item['rule']}) ({item['source']}): "
                     f"{item['explanation']}" for item in bullets)
    else:
        lines.append("  No file-level findings to explain.")
    if verdict.get("snippets"):
        lines.append("Code snippets:")
        for item in verdict["snippets"]:
            label = f" — unwrapped from {item['unwrapped_from']}" if item.get("unwrapped_from") else ""
            lines.append(f"  - {item['file_line']} ({item['rule']}){label}:")
            lines.extend(f"    {line}" for line in item["code"].splitlines())
            if item.get("gemma"):
                lines.append(f"    Gemma: {item['gemma']}")
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
    if recruiter_check:
        lines.append("Recruiter check (web):")
        if not recruiter_check["available"]:
            lines.append("  Search unavailable: set SERPAPI_API_KEY to check public reports.")
        else:
            for entry in recruiter_check["names"]:
                name = entry["name"]
                reports = entry["reports"]
                if reports:
                    lines.append(f"  Scammers have impersonated {name} before ({len(reports)} reports). "
                                 f"Verify this recruiter on {name}'s official careers site before running anything.")
                    lines.extend(f"  - {report['title']} — {report['url']}" for report in reports[:3])
                elif not entry["completed"]:
                    lines.append(f"  No reports could be checked for {name}.")
                else:
                    lines.append(f"  No scam reports found for {name}. That's not proof the recruiter is real.")
            if recruiter_check["failed"]:
                lines.append(f"  {recruiter_check['failed']} of {recruiter_check['total']} searches failed.")
    if memory_notes is None:
        lines.append("memory: off")
    else:
        lines.append("memory: on")
        lines.extend(f"  - {note}" for note in memory_notes)
    lines.append(f"tracing: {'on' if tracing_on else 'off'}")
    if used_llm:
        lines.append(f"Explainer: Gemma (local) read {verdict['snippets_read']} snippets")
    else:
        lines.append("Explainer: built-in rules")
    lines.append("Static checks only — nothing from the repo was executed. Not a guarantee.")
    return "\n".join(lines)
