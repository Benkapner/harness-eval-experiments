#!/usr/bin/env python3
"""Clone each candidate repo shallowly, run harness-eval, record findings, delete.

Writes one JSON object per repo to results.jsonl. Never stores repo contents.
"""
from __future__ import annotations
import json, os, pathlib, random, shutil, subprocess, sys, time

HERE = pathlib.Path(__file__).resolve().parent.parent / "data"
CAND = HERE / "frame_candidates.jsonl"
OUT = HERE / "results.jsonl"
WORK = pathlib.Path("/tmp/scanwork")
MAX_SIZE_KB = 200_000
CLONE_TIMEOUT = 90
SCAN_TIMEOUT = 180

COMPONENT_KEYS = ("skill", "command", "agent", "claude_md", "hooks", "mcp",
                  "context_file", "uncategorized")


def sample(n: int, seed: int = 20260818) -> list[dict]:
    rows = [json.loads(l) for l in CAND.open() if l.strip()]
    rows = [r for r in rows if not r["fork"] and not r["archived"]
            and 0 < r["size_kb"] <= MAX_SIZE_KB]
    rnd = random.Random(seed)
    rnd.shuffle(rows)
    return rows[:n]


def done_set() -> set[str]:
    if not OUT.exists():
        return set()
    return {json.loads(l)["full_name"] for l in OUT.open() if l.strip()}


def flatten(insp: dict) -> list[dict]:
    out = []
    for ctype, items in (insp or {}).items():
        if ctype == "summary" or not isinstance(items, list):
            continue
        for it in items:
            for r in it.get("rules", []):
                if r.get("result") == "pass":
                    continue
                out.append({
                    "rule_id": r.get("rule"),
                    "result": r.get("result"),
                    "component_type": ctype,
                    "component_name": it.get("name"),
                })
    return out


def scan_one(meta: dict) -> dict | None:
    dest = WORK / meta["full_name"].replace("/", "__")
    shutil.rmtree(dest, ignore_errors=True)
    rec = {"full_name": meta["full_name"], "stars": meta["stars"],
           "license": meta["license"], "language": meta["language"],
           "size_kb": meta["size_kb"], "topics": meta["topics"],
           "pushed_at": meta["pushed_at"], "found_by": meta["found_by"]}
    t0 = time.time()
    try:
        subprocess.run(["git", "clone", "--depth", "1", "--single-branch", "-q",
                        meta["clone_url"], str(dest)],
                       timeout=CLONE_TIMEOUT, check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception as e:
        shutil.rmtree(dest, ignore_errors=True)
        rec.update(status="clone_failed", error=type(e).__name__)
        return rec
    try:
        sha = subprocess.run(["git", "-C", str(dest), "rev-parse", "HEAD"],
                             capture_output=True, text=True, timeout=30).stdout.strip()
        rec["commit_sha"] = sha
        p = subprocess.run(["harness-eval", "harness-lint", str(dest), "--format", "json"],
                           capture_output=True, text=True, timeout=SCAN_TIMEOUT)
        data = json.loads(p.stdout)
        rec.update(
            status="ok",
            detected_tools=data.get("detected_tools", []),
            component_count=data.get("component_count", 0),
            budget=data.get("budget", {}),
            triggers=data.get("triggers", {}),
            dependencies=data.get("dependencies", {}),
            summary=(data.get("inspection", {}) or {}).get("summary", {}),
            components_by_type={k: len(v) for k, v in (data.get("inspection") or {}).items()
                                if k != "summary" and isinstance(v, list)},
            findings=flatten(data.get("inspection", {})),
            scan_seconds=round(time.time() - t0, 2),
        )
    except Exception as e:
        rec.update(status="scan_failed", error=f"{type(e).__name__}")
    finally:
        shutil.rmtree(dest, ignore_errors=True)
    return rec


def main():
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 100
    budget_s = float(sys.argv[2]) if len(sys.argv) > 2 else 260
    WORK.mkdir(parents=True, exist_ok=True)
    already = done_set()
    todo = [r for r in sample(3000) if r["full_name"] not in already][:n]
    t0 = time.time()
    from concurrent.futures import ThreadPoolExecutor, as_completed
    import threading
    lock = threading.Lock()
    count = 0
    with OUT.open("a") as f, ThreadPoolExecutor(max_workers=6) as ex:
        futs = {ex.submit(scan_one, m): m for m in todo}
        for fut in as_completed(futs):
            if time.time() - t0 > budget_s:
                for g in futs:
                    g.cancel()
            try:
                rec = fut.result()
            except Exception:
                continue
            if rec is None:
                continue
            with lock:
                f.write(json.dumps(rec) + "\n")
                f.flush()
                count += 1
                if count % 20 == 0:
                    print(f"{count} {rec['full_name']} {rec['status']}", flush=True)
    print("batch done", count)


if __name__ == "__main__":
    main()
