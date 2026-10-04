"""Look up public scam reports without changing the scan verdict."""

import json
import os
import re
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

SCAM = re.compile(r"\b(?:scam|fraud|fake|impersonat\w*)\b", re.I)


def search(company: str | None, recruiter: str | None) -> dict | None:
    names = []
    if company:
        names.append({"name": company, "reports": [], "completed": 0})
    if recruiter:
        names.append({"name": recruiter, "reports": [], "completed": 0})
    if not names:
        return None

    key = os.getenv("SERPAPI_API_KEY")
    check = {"names": names, "failed": 0, "total": 0, "available": bool(key)}
    if not key:
        return check

    queries = []
    if company:
        queries.extend([(f'"{company}" scam', names[0]),
                        (f'"{company}" fake recruiter github', names[0])])
    if recruiter:
        queries.append((f'"{recruiter}" recruiter scam', names[-1]))
    check["total"] = len(queries)
    for query, entry in queries:
        url = "https://serpapi.com/search.json?" + urlencode({"engine": "google", "q": query,
                                                               "api_key": key})
        try:
            with urlopen(Request(url, headers={"User-Agent": "SniffDog"}), timeout=30) as response:
                data = json.load(response)
        except (HTTPError, URLError, TimeoutError, OSError, ValueError):
            check["failed"] += 1
            continue
        organic = data.get("organic_results", []) if isinstance(data, dict) else None
        if not isinstance(data, dict) or data.get("error") or not isinstance(organic, list):
            check["failed"] += 1
            continue
        entry["completed"] += 1
        for item in organic[:5]:
            if not isinstance(item, dict):
                continue
            title, link, snippet = item.get("title"), item.get("link"), item.get("snippet") or ""
            if not all(isinstance(value, str) for value in (title, link, snippet)):
                continue
            text = f"{title} {snippet}"
            if (entry["name"].casefold() in text.casefold() and SCAM.search(text)
                    and not any(report["url"] == link for report in entry["reports"])):
                entry["reports"].append({"title": " ".join(title.split()), "url": link})
    return check
