"""Shared finding and file helpers."""

from dataclasses import asdict, dataclass
import math
import os
from pathlib import Path


SKIP_DIRS = {".git", ".kilo", "node_modules", ".next", "dist", "build", ".venv", "venv", "__pycache__"}
RANK = {"low": 0, "medium": 1, "high": 2}


@dataclass(frozen=True)
class Finding:
    rule: str
    severity: str
    file: str
    line: int | None
    evidence: str
    message: str

    def to_dict(self) -> dict:
        return asdict(self)


def iter_files(root: Path, excludes: tuple[Path, ...] = ()):
    for directory, dirs, files in os.walk(root, followlinks=False):
        relative = Path(directory).relative_to(root)
        dirs[:] = [name for name in dirs
                   if name not in SKIP_DIRS
                   and not (Path(directory) / name).is_symlink()
                   and not any((relative / name) == prefix or prefix in (relative / name).parents
                               for prefix in excludes)]
        for name in files:
            path = Path(directory) / name
            try:
                if not path.is_symlink() and path.stat().st_size <= 2 * 1024 * 1024:
                    yield path
            except OSError:
                continue


def read_text(path: Path) -> str | None:
    try:
        with path.open("rb") as stream:
            head = stream.read(4096)
            if b"\0" in head:
                return None
            return (head + stream.read()).decode("utf-8", errors="replace")
    except OSError:
        return None


def rel(root: Path, path: Path) -> str:
    return path.relative_to(root).as_posix()


def line_of(text: str, position: int) -> int:
    return text.count("\n", 0, position) + 1


def short(text: str, limit: int = 160) -> str:
    flat = " ".join(text.split())
    return flat if len(flat) <= limit else flat[:limit - 1] + "…"


def entropy(value: str) -> float:
    if not value:
        return 0.0
    return -sum((value.count(char) / len(value)) * math.log2(value.count(char) / len(value))
                for char in set(value))


def max_severity(*levels: str) -> str:
    return max(levels, key=RANK.__getitem__)
