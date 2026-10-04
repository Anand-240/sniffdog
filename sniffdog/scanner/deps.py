"""Check package sources and likely misspelled dependencies."""

import json
from pathlib import Path
import re
from urllib.parse import urlparse

from sniffdog.common import Finding, iter_files, line_of, read_text, rel, short


POPULAR = set("react react-dom express cors lodash axios next vue angular rxjs typescript webpack vite "
              "eslint prettier jest mocha chai nodemon dotenv mongoose mongodb prisma sequelize chalk "
              "commander yargs inquirer socket.io firebase uuid moment dayjs jquery bootstrap tailwindcss "
              "postcss autoprefixer bcrypt jsonwebtoken passport puppeteer playwright sharp multer "
              "fastify koa redux zod winston pino ws graphql apollo-server nodemailer rimraf "
              "glob minimist semver debug tslib".split())
REMOTE = re.compile(r"^(?:git\+|git:|https?://|github:|file:|link:)|^[\w.-]+/[\w.-]+(?:#.*)?$")


def distance_one(left: str, right: str) -> bool:
    if abs(len(left) - len(right)) > 1:
        return False
    if len(left) == len(right):
        return sum(a != b for a, b in zip(left, right)) == 1
    if len(left) > len(right):
        left, right = right, left
    return any(left == right[:i] + right[i + 1:] for i in range(len(right)))


def scan(root: Path, excludes: tuple[Path, ...] = ()) -> list[Finding]:
    findings = []
    if Path("node_modules") not in excludes and (root / "node_modules").is_dir():
        findings.append(Finding("committed-node-modules", "medium", "node_modules", None,
                                "node_modules/", "This repo includes installed dependencies; inspect them before use."))
    for path in iter_files(root, excludes):
        file = rel(root, path)
        if path.name == ".npmrc":
            text = read_text(path)
            if text is None:
                continue
            for match in re.finditer(r"^\s*registry\s*=\s*(\S+)", text, re.M):
                try:
                    host = urlparse(match.group(1)).hostname
                except ValueError:
                    host = None
                if host != "registry.npmjs.org":
                    findings.append(Finding("npm-registry", "high", file, line_of(text, match.start()),
                                            short(match.group()), "This repo points npm at a nonstandard registry."))
        elif path.name == "package.json":
            text = read_text(path)
            if text is None:
                continue
            try:
                data = json.loads(text)
            except json.JSONDecodeError:
                continue
            if not isinstance(data, dict):
                continue
            for field in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
                versions = data.get(field, {})
                if not isinstance(versions, dict):
                    continue
                for name, version in versions.items():
                    if not isinstance(name, str) or not isinstance(version, str):
                        continue
                    position = text.find(f'"{name}"')
                    line = line_of(text, position) if position >= 0 else None
                    if REMOTE.search(version):
                        findings.append(Finding("remote-dependency", "medium", file, line,
                                                short(f"{name}: {version}"),
                                                "This dependency comes from a repository, URL or local path."))
                    if not name.startswith("@") and len(name) >= 4:
                        target = next((popular for popular in sorted(POPULAR)
                                       if distance_one(name, popular)), None)
                        if target:
                            findings.append(Finding("typosquat", "medium", file, line,
                                                    f"{name} resembles {target}",
                                                    "This dependency name is one edit away from a popular package."))
        elif path.name == "package-lock.json":
            text = read_text(path)
            if text is None:
                continue
            count = 0
            for match in re.finditer(r'"resolved"\s*:\s*"(https?://[^"\s]+)"', text):
                try:
                    host = urlparse(match.group(1)).hostname
                except ValueError:
                    host = None
                if host != "registry.npmjs.org":
                    findings.append(Finding("lockfile-source", "medium", file, line_of(text, match.start()),
                                            short(match.group(1)),
                                            "This lockfile fetches a package outside the official npm registry."))
                    count += 1
                    if count == 5:
                        break
    return findings
