"""Clone a remote repository without running repository code."""

import os
from pathlib import Path
import re
import subprocess


URL = re.compile(r"https://[A-Za-z0-9.-]+/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:\.git)?\Z")


def safe_clone(url: str, dest: Path) -> None:
    if not URL.fullmatch(url) or ".." in url or url.endswith("/."):
        raise ValueError("Expected a plain https://host/owner/repo URL.")
    env = os.environ.copy()
    env.update(GIT_TERMINAL_PROMPT="0", GIT_LFS_SKIP_SMUDGE="1",
               GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1")
    command = ["git", "-c", "core.hooksPath=/dev/null", "-c", "core.symlinks=false",
               "-c", "protocol.allow=never", "-c", "protocol.https.allow=always",
               "clone", "--depth", "1", "--no-tags", "--single-branch", url, str(dest)]
    subprocess.run(command, env=env, check=True, timeout=180, capture_output=True, text=True)
