"""Check assets that may hide executable text."""

from pathlib import Path
import re

from sniffdog.common import Finding, iter_files, line_of, read_text, rel, short


MAGIC = {
    ".png": (b"\x89PNG\r\n\x1a\n",), ".jpg": (b"\xff\xd8\xff",),
    ".jpeg": (b"\xff\xd8\xff",), ".gif": (b"GIF87a", b"GIF89a"),
    ".ico": (b"\x00\x00\x01\x00",), ".woff": (b"wOFF",),
    ".woff2": (b"wOF2",), ".ttf": (b"\x00\x01\x00\x00",),
    ".otf": (b"OTTO",),
}
CODE = {".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx"}
READ_ASSET = re.compile(r"readFileSync\s*\([^\n]*?\.(?:png|jpe?g|gif|ico|woff2?|ttf|otf)\b")
EVAL = re.compile(r"\beval\s*\(|\bnew\s+Function\s*\(")
JS_LIKE = re.compile(r"\b(?:const|let|var|function|module\.exports|console\.log|require\s*\()\b")
BASE64 = re.compile(r"[A-Za-z0-9+/]{5000,}={0,2}")


def scan(root: Path) -> list[Finding]:
    findings = []
    for path in iter_files(root):
        suffix = path.suffix.lower()
        file = rel(root, path)
        if suffix in MAGIC:
            try:
                head = path.read_bytes()[:256]
            except OSError:
                continue
            if not any(head.startswith(magic) for magic in MAGIC[suffix]):
                evidence = short(head.decode("utf-8", errors="replace"))
                javascript = bool(JS_LIKE.search(evidence))
                severity = "high" if javascript else "medium"
                message = (f"This {suffix} file is actually JavaScript code pretending to be a font/image."
                           if javascript else "This image or font file does not have the expected file signature.")
                findings.append(Finding("disguised-asset", severity, file, 1, evidence,
                                        message))
        elif suffix == ".svg":
            text = read_text(path)
            if text is None:
                continue
            close = re.search(r"</svg\s*>", text, re.I)
            if close and text[close.end():].strip():
                findings.append(Finding("svg-trailing-code", "high", file, line_of(text, close.end()),
                                        short(text[close.end():]), "This SVG has content after its closing tag."))
            script = re.search(r"<script\b", text, re.I)
            if script:
                findings.append(Finding("svg-script", "medium", file, line_of(text, script.start()),
                                        "<script", "This SVG contains a script tag."))
            encoded = next((m for m in BASE64.finditer(text)
                            if not re.search(r"data:image[^\n]{0,100}$", text[max(0, m.start() - 100):m.start()], re.I)), None)
            if encoded:
                findings.append(Finding("svg-base64", "medium", file, line_of(text, encoded.start()),
                                        short(encoded.group()), "This SVG contains a long encoded string."))
        elif suffix in CODE:
            text = read_text(path)
            if text is None:
                continue
            match = READ_ASSET.search(text)
            if match and EVAL.search(text):
                findings.append(Finding("asset-evaluation", "high", file, line_of(text, match.start()),
                                        short(match.group()), "This code reads an image or font and evaluates text as code."))
    return findings
