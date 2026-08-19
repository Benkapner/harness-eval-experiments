#!/usr/bin/env python3
"""Collect candidate repositories that may contain AI code-agent harness setups.

Sampling frame: GitHub repository search (unauthenticated). Code search would be
a better frame but requires authentication, so we use topic/README queries and
document the resulting bias.
"""
from __future__ import annotations
import json, time, sys, urllib.request, urllib.parse, pathlib

OUT = pathlib.Path(__file__).resolve().parent.parent / "data" / "frame_candidates.jsonl"

QUERIES = [
    "topic:claude-code",
    "topic:claude-code-skills",
    "topic:agent-skills",
    "topic:claude-skills",
    "topic:agents-md",
    "topic:cursor-rules",
    "topic:copilot-instructions",
    "topic:opencode",
    '"CLAUDE.md" in:readme',
    '"AGENTS.md" in:readme',
    '"claude/agents" in:readme',
    '".claude/skills" in:readme',
    "topic:ai-agents topic:developer-tools",
    "topic:claude-code-hooks",
    "topic:subagents",
]
SORTS = ["stars", "updated"]
PER_PAGE = 100
PAGES = 3


def get(url: str):
    req = urllib.request.Request(url, headers={"Accept": "application/vnd.github+json",
                                               "User-Agent": "harness-corpus/1.0"})
    for attempt in range(6):
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                return json.load(r)
        except Exception as e:  # rate limit / transient
            wait = 20 * (attempt + 1)
            print(f"  retry in {wait}s ({e})", file=sys.stderr)
            time.sleep(wait)
    return None


def main():
    import os
    lo=int(os.environ.get("QLO","0")); hi=int(os.environ.get("QHI","99"))
    seen: dict[str, dict] = {}
    if OUT.exists():
        for line in OUT.read_text().splitlines():
            if line.strip():
                r = json.loads(line)
                seen[r["full_name"]] = r
    for q in QUERIES[lo:hi]:
        for sort in SORTS:
            for page in range(1, PAGES + 1):
                url = ("https://api.github.com/search/repositories?q="
                       + urllib.parse.quote(q)
                       + f"&sort={sort}&order=desc&per_page={PER_PAGE}&page={page}")
                data = get(url)
                time.sleep(7)  # 10 search requests/minute unauthenticated
                if not data or "items" not in data:
                    break
                new = 0
                for it in data["items"]:
                    fn = it["full_name"]
                    if fn in seen:
                        continue
                    seen[fn] = {
                        "full_name": fn,
                        "clone_url": it["clone_url"],
                        "stars": it["stargazers_count"],
                        "created_at": it["created_at"],
                        "pushed_at": it["pushed_at"],
                        "language": it.get("language"),
                        "license": (it.get("license") or {}).get("spdx_id"),
                        "fork": it["fork"],
                        "archived": it["archived"],
                        "size_kb": it["size"],
                        "topics": it.get("topics", []),
                        "found_by": f"{q}|{sort}",
                    }
                    new += 1
                print(f"{q} [{sort}] p{page}: +{new} (total {len(seen)})", flush=True)
                with OUT.open("w") as f:
                    for r in seen.values():
                        f.write(json.dumps(r) + "\n")
                if len(data["items"]) < PER_PAGE:
                    break
    with OUT.open("w") as f:
        for r in seen.values():
            f.write(json.dumps(r) + "\n")
    print(f"wrote {len(seen)} candidates -> {OUT}")


if __name__ == "__main__":
    main()
