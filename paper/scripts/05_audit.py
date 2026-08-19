#!/usr/bin/env python3
"""Re-scan the census of repos carrying rare SETUP-scope findings and capture the
finding messages plus surrounding evidence, for manual precision audit."""
from __future__ import annotations
import json, pathlib, shutil, subprocess, time
from concurrent.futures import ThreadPoolExecutor, as_completed

HERE = pathlib.Path(__file__).resolve().parent.parent / "data"
TARGETS = json.load((HERE / "audit_targets.json").open())
CAND = {json.loads(l)["full_name"]: json.loads(l)
        for l in (HERE / "frame_candidates.jsonl").open() if l.strip()}
OUT = HERE / "audit_evidence.jsonl"
WORK = pathlib.Path("/tmp/auditwork")
RARE = {"cross-component-flow", "permission-escalation", "overpermissive-grants",
        "mcp-skill-alignment", "circular-references", "multi-assistant-drift"}


def done():
    if not OUT.exists():
        return set()
    return {json.loads(l)["full_name"] for l in OUT.open() if l.strip()}


def one(name: str) -> dict | None:
    meta = CAND.get(name)
    if not meta:
        return None
    dest = WORK / name.replace("/", "__")
    shutil.rmtree(dest, ignore_errors=True)
    rec = {"full_name": name, "expected": TARGETS[name]}
    try:
        subprocess.run(["git", "clone", "--depth", "1", "--single-branch", "-q",
                        meta["clone_url"], str(dest)], timeout=120, check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        rec["sha"] = subprocess.run(["git", "-C", str(dest), "rev-parse", "HEAD"],
                                    capture_output=True, text=True).stdout.strip()
        p = subprocess.run(["harness-eval", "harness-lint", str(dest)],
                           capture_output=True, text=True, timeout=240)
        lines = p.stdout.splitlines()
        keep, ctx = [], 0
        for i, ln in enumerate(lines):
            if any(r in ln for r in RARE):
                keep.extend(lines[max(0, i - 1):i + 4])
                ctx += 1
        rec["evidence"] = [l.strip() for l in keep if l.strip()][:80]
        rec["n_blocks"] = ctx
        # inventory for judging
        inv = {}
        for sub in (".claude", ".cursor", ".github", ".gemini", ".opencode"):
            d = dest / sub
            if d.is_dir():
                inv[sub] = sorted(str(x.relative_to(dest)) for x in d.rglob("*")
                                  if x.is_file())[:40]
        for f in ("CLAUDE.md", "AGENTS.md", "GEMINI.md", ".cursorrules"):
            if (dest / f).is_file():
                inv[f] = (dest / f).stat().st_size
        rec["inventory"] = inv
        rec["status"] = "ok"
    except Exception as e:
        rec["status"] = f"fail:{type(e).__name__}"
    finally:
        shutil.rmtree(dest, ignore_errors=True)
    return rec


def main():
    WORK.mkdir(parents=True, exist_ok=True)
    todo = [n for n in TARGETS if n not in done()]
    t0 = time.time()
    with OUT.open("a") as f, ThreadPoolExecutor(max_workers=5) as ex:
        futs = {ex.submit(one, n): n for n in todo}
        for fut in as_completed(futs):
            if time.time() - t0 > 250:
                for g in futs:
                    g.cancel()
            try:
                rec = fut.result()
            except Exception:
                continue
            if rec:
                f.write(json.dumps(rec) + "\n")
                f.flush()
                print(rec["full_name"], rec.get("status"), rec.get("n_blocks"), flush=True)


if __name__ == "__main__":
    main()
