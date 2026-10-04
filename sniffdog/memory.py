"""Remember scans and match harmless descriptions of known techniques."""

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sys
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from sniffdog.common import Finding


def connect():
    uri = os.getenv("MONGODB_URI")
    if not uri:
        return None
    try:
        from pymongo import MongoClient
        from pymongo.errors import PyMongoError
    except ImportError:
        return None
    try:
        client = MongoClient(uri, serverSelectionTimeoutMS=2000,
                             connectTimeoutMS=2000, socketTimeoutMS=2000)
        client.admin.command("ping")
        return client
    except PyMongoError:
        return None


def embed(value: str) -> list[float]:
    host = os.getenv("OLLAMA_HOST", "http://localhost:11434").rstrip("/")
    parsed = urlparse(host)
    if parsed.scheme != "http" or parsed.hostname not in {"localhost", "127.0.0.1", "::1"}:
        raise ValueError("Ollama embeddings must use a local host")
    payload = {"model": os.getenv("OLLAMA_EMBED_MODEL", "nomic-embed-text"), "input": value}
    request = Request(f"{host}/api/embed", data=json.dumps(payload).encode(),
                      headers={"Content-Type": "application/json"}, method="POST")
    with urlopen(request, timeout=30) as response:
        vector = json.load(response)["embeddings"][0]
    if not isinstance(vector, list) or len(vector) != 768:
        raise ValueError("Ollama returned an unexpected embedding size")
    return vector


def seed() -> int | None:
    client = connect()
    if client is None:
        return None
    try:
        from pymongo.errors import PyMongoError
        path = Path(__file__).resolve().parents[1] / "patterns" / "known_patterns.json"
        if not path.is_file():
            path = Path(sys.prefix) / "share" / "sniffdog" / "known_patterns.json"
        patterns = json.loads(path.read_text(encoding="utf-8"))
        collection = client.sniffdog.patterns
        for pattern in patterns:
            vector = embed(f"{pattern['description']} {pattern['snippet']}")
            collection.update_one({"name": pattern["name"]},
                                  {"$set": {**pattern, "embedding": vector}}, upsert=True)
        return len(patterns)
    except (PyMongoError, HTTPError, URLError, TimeoutError, OSError, ValueError, KeyError, TypeError):
        return None
    finally:
        client.close()


def notes(client, url: str | None, findings: list[Finding]) -> list[str] | None:
    try:
        from pymongo.errors import PyMongoError
        result = []
        if url:
            previous = client.sniffdog.scans.find_one({"repo_url": url}, sort=[("timestamp", -1)])
            if previous:
                date = previous["timestamp"].date().isoformat()
                result.append(f"Scanned before on {date}: {previous['verdict']}")
        for finding in findings:
            if finding.severity not in {"medium", "high"}:
                continue
            vector = embed(finding.evidence)
            pipeline = [{"$vectorSearch": {"index": "pattern_index", "path": "embedding",
                                            "queryVector": vector, "numCandidates": 30, "limit": 3}},
                        {"$project": {"_id": 0, "name": 1,
                                      "score": {"$meta": "vectorSearchScore"}}}]
            for match in client.sniffdog.patterns.aggregate(pipeline):
                note = f"resembles known technique: {match['name']}"
                if match["score"] >= 0.85 and note not in result:
                    result.append(note)
        return result
    except (PyMongoError, HTTPError, URLError, TimeoutError, OSError, ValueError, KeyError, TypeError):
        return None


def save(client, url: str, commit: str, verdict: str, findings: list[Finding]) -> bool:
    try:
        from pymongo.errors import PyMongoError
        client.sniffdog.scans.insert_one({"repo_url": url, "commit": commit,
                                          "timestamp": datetime.now(timezone.utc),
                                          "verdict": verdict,
                                          "rules": [finding.rule for finding in findings]})
        return True
    except PyMongoError:
        return False
