"""Fetch public GitHub repository and owner signals."""

from datetime import datetime, timezone
import json
import os
import re
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from sniffdog.common import Finding


def inspect(url: str) -> tuple[dict, list[Finding]]:
    parsed = urlparse(url)
    parts = parsed.path.strip("/").split("/")
    if parsed.hostname != "github.com" or len(parts) != 2:
        return {}, []
    owner, repo = parts
    repo = repo.removesuffix(".git")
    if not owner or not repo:
        return {}, []
    base = "https://api.github.com"
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "SniffDog"}
    token = os.getenv("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        request = Request(f"{base}/repos/{owner}/{repo}", headers=headers)
        with urlopen(request, timeout=10) as response:
            repository = json.load(response)
        request = Request(f"{base}/users/{owner}", headers=headers)
        with urlopen(request, timeout=10) as response:
            account = json.load(response)
        request = Request(f"{base}/repos/{owner}/{repo}/commits?per_page=1", headers=headers)
        with urlopen(request, timeout=10) as response:
            commits = json.load(response)
            link = response.headers.get("Link", "")
        last = re.search(r"[?&]page=(\d+)>;\s*rel=\"last\"", link)
        count = int(last.group(1)) if last else len(commits)
        now = datetime.now(timezone.utc)
        owner_age = (now - datetime.fromisoformat(account["created_at"].replace("Z", "+00:00"))).days
        repo_age = (now - datetime.fromisoformat(repository["created_at"].replace("Z", "+00:00"))).days
        stars = int(repository["stargazers_count"])
        public_repos = int(account["public_repos"])
    except (HTTPError, URLError, TimeoutError, OSError, ValueError, KeyError, TypeError) as error:
        return {"error": f"GitHub metadata unavailable: {error}"}, []
    facts = {"owner": owner, "repo": repo, "owner_age_days": owner_age,
             "repo_age_days": repo_age, "commits": count, "stars": stars,
             "owner_public_repos": public_repos}
    findings = []
    if owner_age < 90:
        findings.append(Finding("new-github-owner", "medium", "github.com", None,
                                f"Owner account age: {owner_age} days",
                                "This GitHub owner account is less than 90 days old."))
    if count <= 2:
        findings.append(Finding("few-commits", "medium", "github.com", None,
                                f"{count} commits", "This GitHub repository has at most two commits."))
    if repo_age < 14:
        findings.append(Finding("new-github-repo", "low", "github.com", None,
                                f"Repository age: {repo_age} days",
                                "This GitHub repository is less than 14 days old."))
    if stars == 0 and public_repos <= 2:
        findings.append(Finding("little-github-history", "low", "github.com", None,
                                f"{stars} stars; {public_repos} public repos",
                                "This owner has little public GitHub history."))
    return facts, findings
