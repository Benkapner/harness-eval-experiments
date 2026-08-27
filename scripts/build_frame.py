#!/usr/bin/env python3
"""Build the repository frame from the GitHub search API plus curated lists.

Discovery channels, recorded per repository so they can be compared:
  topic:<name>      GitHub topic search, sorted by stars and by recency, 3 pages each
  readme:<term>     README text search for canonical context-file names
  curated:<list>    repositories linked from public awesome-lists of agent configurations

Unauthenticated search is limited to 10 requests per minute; the script sleeps
to stay under it and is resumable (already-fetched pages are cached).
Output: data/frame.jsonl, one record per unique repository, forks and archived
repositories excluded, with the channels that surfaced it.
"""
from __future__ import annotations

import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import quote

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data"
DATA.mkdir(exist_ok=True)
FRAME = DATA / "frame.jsonl"
PAGES = DATA / "frame_pages.jsonl"

TOPICS = [
    "claude-code", "agent-skills", "agents-md", "cursorrules", "cursor-rules",
    "copilot-instructions", "opencode", "subagents", "claude-skills", "claude-code-skills",
    "claude-code-plugin", "gemini-cli", "windsurf-rules", "codex-cli", "mcp-config",
]
README_TERMS = ["CLAUDE.md", "AGENTS.md", "copilot-instructions.md", ".cursorrules", "GEMINI.md"]
CURATED = {
    "awesome-claude-code": "https://raw.githubusercontent.com/hesreallyhim/awesome-claude-code/main/README.md",
    "awesome-cursorrules": "https://raw.githubusercontent.com/PatrickJS/awesome-cursorrules/main/README.md",
    "awesome-agent-skills": "https://raw.githubusercontent.com/heyfoz/awesome-agent-skills/main/README.md",
    "awesome-claude-skills": "https://raw.githubusercontent.com/ComposioHQ/awesome-claude-skills/main/README.md",
    "awesome-copilot": "https://raw.githubusercontent.com/github/awesome-copilot/main/README.md",
}
SORTS = ["stars", "updated"]
PAGE_COUNT = 3
API = "https://api.github.com/search/repositories"
TOKEN = os.environ.get("GITHUB_TOKEN")
MIN_INTERVAL = 6.5 if not TOKEN else 2.1


def _get(url: str) -> tuple[int, bytes]:
    req = urllib.request.Request(url, headers={"Accept": "application/vnd.github+json",
                                               "User-Agent": "harness-eval-study"})
    if TOKEN:
        req.add_header("Authorization", f"Bearer {TOKEN}")
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()
    except Exception as e:  # noqa: BLE001
        return 0, str(e).encode()


def _load_pages() -> dict[str, list[dict]]:
    out: dict[str, list[dict]] = {}
    if PAGES.exists():
        for line in PAGES.read_text().splitlines():
            if line.strip():
                rec = json.loads(line)
                out[rec["key"]] = rec["items"]
    return out


def _search(q: str, sort: str, page: int, cache: dict, last_call: list[float]) -> list[dict]:
    key = f"{q}|{sort}|{page}"
    if key in cache:
        return cache[key]
    url = f"{API}?q={quote(q)}&sort={sort}&order=desc&per_page=30&page={page}"
    for attempt in range(6):
        wait = MIN_INTERVAL - (time.time() - last_call[0])
        if wait > 0:
            time.sleep(wait)
        status, body = _get(url)
        last_call[0] = time.time()
        if status == 200:
            items = json.loads(body).get("items", [])
            slim = [{"full_name": it["full_name"], "stars": it.get("stargazers_count", 0),
                     "fork": it.get("fork", False), "archived": it.get("archived", False),
                     "pushed_at": it.get("pushed_at"), "default_branch": it.get("default_branch", "main"),
                     "topics": it.get("topics", [])} for it in items]
            cache[key] = slim
            with PAGES.open("a") as f:
                f.write(json.dumps({"key": key, "items": slim}) + "\n")
            print(f"  {key}: {len(slim)}", file=sys.stderr, flush=True)
            return slim
        if status in (403, 429):
            print(f"  rate limited on {key}, sleeping 65s (attempt {attempt})", file=sys.stderr, flush=True)
            time.sleep(65)
            continue
        if status == 422:
            cache[key] = []
            return []
        print(f"  {key}: HTTP {status}", file=sys.stderr, flush=True)
        time.sleep(10)
    return []


def _curated() -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    pat = re.compile(r"https?://github\.com/([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)")
    for name, url in CURATED.items():
        status, body = _get(url)
        if status != 200:
            print(f"  curated {name}: HTTP {status}", file=sys.stderr, flush=True)
            continue
        repos = set()
        for m in pat.finditer(body.decode("utf-8", "replace")):
            fn = m.group(1).rstrip(").,")
            if fn.endswith(".git"):
                fn = fn[:-4]
            if fn.count("/") == 1:
                repos.add(fn)
        out[name] = repos
        print(f"  curated {name}: {len(repos)} repos", file=sys.stderr, flush=True)
    return out


def main() -> None:
    cache = _load_pages()
    last_call = [0.0]
    frame: dict[str, dict] = {}

    def add(item: dict, channel: str) -> None:
        fn = item["full_name"]
        rec = frame.setdefault(fn, {"full_name": fn, "channels": [], "stars": item.get("stars", 0),
                                    "fork": item.get("fork", False), "archived": item.get("archived", False),
                                    "default_branch": item.get("default_branch", "main")})
        if channel not in rec["channels"]:
            rec["channels"].append(channel)
        rec["stars"] = max(rec["stars"], item.get("stars", 0))

    print("topic searches", file=sys.stderr, flush=True)
    for t in TOPICS:
        for sort in SORTS:
            for page in range(1, PAGE_COUNT + 1):
                items = _search(f"topic:{t}", sort, page, cache, last_call)
                for it in items:
                    add(it, f"topic:{t}")
                if len(items) < 30:
                    break
    print("readme searches", file=sys.stderr, flush=True)
    for term in README_TERMS:
        for sort in SORTS:
            for page in range(1, PAGE_COUNT + 1):
                items = _search(f'"{term}" in:readme', sort, page, cache, last_call)
                for it in items:
                    add(it, f"readme:{term}")
                if len(items) < 30:
                    break
    print("curated lists", file=sys.stderr, flush=True)
    for name, repos in _curated().items():
        for fn in sorted(repos):
            add({"full_name": fn}, f"curated:{name}")

    kept = [r for r in frame.values() if not r["fork"] and not r["archived"]]
    with FRAME.open("w") as f:
        for r in sorted(kept, key=lambda r: r["full_name"]):
            f.write(json.dumps(r) + "\n")
    print(f"frame: {len(frame)} unique, {len(kept)} kept", file=sys.stderr, flush=True)


if __name__ == "__main__":
    main()
