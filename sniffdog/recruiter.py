"""Check optional public search results for recruiter scam reports."""

import json
import os
import re
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from sniffdog.common import Finding, short


SCAM = re.compile(r"\b(?:scam|fraud|fake|malware|phishing|lazarus|contagious interview|north korea)\b", re.I)


def search(company: str | None, recruiter: str | None) -> tuple[list[dict], list[Finding], str | None]:
    key = os.getenv("SERPAPI_API_KEY")
    if not key or not (company or recruiter):
        return [], [], None
    queries = []
    if company:
        queries.extend([(f'"{company}" scam', company),
                        (f'"{company}" fake recruiter github', company)])
    if recruiter:
        queries.append((f'"{recruiter}" recruiter scam', recruiter))
    results = []
    findings = []
    for query, name in queries:
        url = "https://serpapi.com/search.json?" + urlencode({"engine": "google", "q": query,
                                                               "api_key": key})
        try:
            with urlopen(Request(url, headers={"User-Agent": "SniffDog"}), timeout=10) as response:
                data = json.load(response)
        except (HTTPError, URLError, TimeoutError, OSError, ValueError) as error:
            return results, findings, f"Recruiter search unavailable: {error}"
        if not isinstance(data, dict):
            return results, findings, "Recruiter search returned an invalid response."
        if data.get("error"):
            return results, findings, f"Recruiter search unavailable: {data['error']}"
        for item in data.get("organic_results", [])[:5]:
            if not isinstance(item, dict):
                continue
            result = {field: item.get(field, "") for field in ("title", "link", "snippet")}
            results.append(result)
            text = f"{result['title']} {result['snippet']}"
            if (len(findings) < 3 and name.casefold() in text.casefold() and SCAM.search(text)):
                findings.append(Finding("recruiter-scam-report", "medium", result["link"], None,
                                        short(text),
                                        f"A search result mentions {name} alongside a scam warning."))
    return results, findings, None
