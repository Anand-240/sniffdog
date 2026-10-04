"""Check VS Code tasks and automatic task settings."""

import json
from pathlib import Path
import re

from sniffdog.common import Finding, iter_files, line_of, read_text, rel, short


def strip_jsonc(text: str) -> str:
    out = []
    index = 0
    quoted = False
    escaped = False
    while index < len(text):
        char = text[index]
        nxt = text[index + 1] if index + 1 < len(text) else ""
        if quoted:
            out.append(char)
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
            index += 1
        elif char == '"':
            quoted = True
            out.append(char)
            index += 1
        elif char == "/" and nxt == "/":
            end = text.find("\n", index)
            if end < 0:
                end = len(text)
            out.extend(" " * (end - index))
            index = end
        elif char == "/" and nxt == "*":
            end = text.find("*/", index + 2)
            end = len(text) if end < 0 else end + 2
            out.extend("\n" if c == "\n" else " " for c in text[index:end])
            index = end
        else:
            out.append(char)
            index += 1
    cleaned = "".join(out)
    result = []
    quoted = False
    escaped = False
    for index, char in enumerate(cleaned):
        if quoted:
            result.append(char)
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
            result.append(char)
        elif char == "," and re.match(r"\s*[}\]]", cleaned[index + 1:]):
            result.append(" ")
        else:
            result.append(char)
    return "".join(result)


def scan(root: Path, excludes: tuple[Path, ...] = ()) -> list[Finding]:
    findings = []
    for path in iter_files(root, excludes):
        if path.parent.name != ".vscode" or path.name not in {"tasks.json", "settings.json"}:
            continue
        text = read_text(path)
        if text is None:
            continue
        try:
            data = json.loads(strip_jsonc(text))
        except json.JSONDecodeError:
            if path.name == "tasks.json" and "folderOpen" in text:
                findings.append(Finding("vscode-folder-open", "high", rel(root, path),
                                        line_of(text, text.index("folderOpen")), "folderOpen",
                                        "This task may run automatically when you open the folder in VS Code."))
            continue
        if not isinstance(data, dict):
            continue
        if path.name == "settings.json":
            if data.get("task.allowAutomaticTasks") == "on":
                position = text.find("task.allowAutomaticTasks")
                findings.append(Finding("vscode-auto-tasks", "medium", rel(root, path),
                                        line_of(text, position), "task.allowAutomaticTasks: on",
                                        "This setting allows automatic VS Code tasks."))
        else:
            for task in data.get("tasks", []):
                if not isinstance(task, dict) or not isinstance(task.get("runOptions"), dict):
                    continue
                if task["runOptions"].get("runOn") != "folderOpen":
                    continue
                command = task.get("command", "")
                args = task.get("args", [])
                evidence = short(f"{command} {' '.join(map(str, args)) if isinstance(args, list) else args}")
                position = text.find("folderOpen")
                findings.append(Finding("vscode-folder-open", "high", rel(root, path),
                                        line_of(text, position), evidence,
                                        "This task runs automatically when you open the folder in VS Code."))
    return findings
