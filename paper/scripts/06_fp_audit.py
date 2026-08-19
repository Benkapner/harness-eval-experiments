#!/usr/bin/env python3
"""Collect per-finding evidence for a manual false-positive audit.

For a stratified sample of repositories, re-scan with full JSON output, resolve
each finding back to the component file that produced it, and extract the source
lines a human needs in order to judge whether the finding is a true positive.

Output: data/fp_evidence.jsonl, one record per finding, containing the rule, the
message, and a short evidence window. No repository content is retained beyond
those windows.
"""
from __future__ import annotations
import json, pathlib, random, re, shutil, subprocess, sys, time
from concurrent.futures import ThreadPoolExecutor, as_completed

HERE = pathlib.Path(__file__).resolve().parent.parent
DATA = HERE / "data"
OUT = DATA / "fp_evidence.jsonl"
WORK = pathlib.Path("/tmp/fpwork")
LINE_RE = re.compile(r"[Ll]ine (\d+)")
QUOTED = re.compile(r"'([^']{1,120})'")


def resolve_component(root: pathlib.Path, ctype: str, name: str) -> pathlib.Path | None:
    """Best-effort map from (component type, name) back to its file."""
    pats = {
        "skill": [f"**/skills/{name}/SKILL.md", f"**/skills/{name}.md"],
        "command": [f"**/commands/{name}.md", f"**/commands/**/{name}.md"],
        "agent": [f"**/agents/{name}.md", f"**/subagents/{name}.md"],
        "claude_md": ["CLAUDE.md", "AGENTS.md", "GEMINI.md",
                      ".github/copilot-instructions.md"],
        "hooks": ["**/settings.json", "**/settings.local.json"],
        "mcp": ["**/.mcp.json", "**/mcp.json"],
        "context_file": ["CLAUDE.md", "AGENTS.md"],
    }.get(ctype, [f"**/{name}", f"**/{name}.md"])
    for pat in pats:
        for hit in root.glob(pat):
            if hit.is_file():
                return hit
    return None


def window(path: pathlib.Path, line: int | None, msg: str) -> dict:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return {"evidence": None}
    lines = text.split("\n")
    out: dict = {"file": path.name, "n_lines": len(lines)}
    if line and 1 <= line <= len(lines):
        lo, hi = max(0, line - 4), min(len(lines), line + 4)
        out["evidence"] = [f"{i+1}: {lines[i][:200]}" for i in range(lo, hi)]
        out["target_line"] = lines[line - 1][:300]
    else:
        # no line number: give frontmatter plus opening body, enough for
        # description-quality, token-budget and orphan-style findings
        out["evidence"] = [f"{i+1}: {l[:200]}" for i, l in enumerate(lines[:25])]
        # if the message quotes a string, show every line containing it
        q = QUOTED.findall(msg)
        hits = []
        for token in q[:2]:
            for i, l in enumerate(lines):
                if token in l:
                    hits.append(f"{i+1}: {l[:200]}")
                    if len(hits) > 6:
                        break
        if hits:
            out["quoted_hits"] = hits[:8]
    return out


def scan_repo(meta: dict) -> list[dict]:
    name = meta["full_name"]
    dest = WORK / name.replace("/", "__")
    shutil.rmtree(dest, ignore_errors=True)
    recs: list[dict] = []
    try:
        subprocess.run(["git", "clone", "--depth", "1", "--single-branch", "-q",
                        meta["clone_url"], str(dest)], timeout=120, check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        p = subprocess.run(["harness-eval", "harness-lint", str(dest), "--format", "json"],
                           capture_output=True, text=True, timeout=240)
        data = json.loads(p.stdout)
        for ctype, items in (data.get("inspection") or {}).items():
            if ctype == "summary" or not isinstance(items, list):
                continue
            for it in items:
                cpath = resolve_component(dest, ctype, it.get("name", ""))
                for f in it.get("findings", []) or []:
                    msg = f.get("message", "")
                    m = LINE_RE.search(msg)
                    ln = int(m.group(1)) if m else None
                    rec = {
                        "repo": name,
                        "klass": meta.get("klass"),
                        "rule": f.get("rule"),
                        "severity": f.get("severity"),
                        "component_type": ctype,
                        "component": it.get("name"),
                        "message": msg,
                        "suggestion": f.get("suggestion"),
                        "resolved_file": str(cpath.relative_to(dest)) if cpath else None,
                    }
                    if cpath:
                        rec.update(window(cpath, ln, msg))
                    recs.append(rec)
    except Exception as e:
        recs.append({"repo": name, "error": f"{type(e).__name__}"})
    finally:
        shutil.rmtree(dest, ignore_errors=True)
    return recs


def main() -> None:
    n_repos = int(sys.argv[1]) if len(sys.argv) > 1 else 40
    budget = float(sys.argv[2]) if len(sys.argv) > 2 else 250
    seed = 4242
    rows = [json.loads(l) for l in (DATA / "corpus_manifest.jsonl").open() if l.strip()]
    rows = [r for r in rows if r.get("status") == "ok" and r.get("findings_total", 0) > 0]
    rnd = random.Random(seed)
    strata: dict[str, list] = {}
    for r in rows:
        strata.setdefault(r["klass"], []).append(r)
    picks: list[dict] = []
    # over-sample SETUP, the population the paper's claims are about
    quota = {"SETUP": 0.5, "COLLECTION": 0.25, "INSTRUCTION_ONLY": 0.25}
    for k, frac in quota.items():
        pool = strata.get(k, [])
        rnd.shuffle(pool)
        picks += pool[:int(n_repos * frac)]
    done = set()
    if OUT.exists():
        done = {json.loads(l).get("repo") for l in OUT.open() if l.strip()}
    picks = [p for p in picks if p["full_name"] not in done]
    WORK.mkdir(parents=True, exist_ok=True)
    t0 = time.time()
    import threading
    lock = threading.Lock()
    with ThreadPoolExecutor(max_workers=5) as ex:
        futs = {ex.submit(scan_repo, m): m for m in picks}
        for fut in as_completed(futs):
            if time.time() - t0 > budget:
                for g in futs:
                    g.cancel()
            try:
                recs = fut.result()
            except Exception:
                continue
            if not recs:
                continue
            with lock, OUT.open("a") as fh:
                for r in recs:
                    fh.write(json.dumps(r) + "\n")
            print(f"{recs[0].get('repo')}: {len(recs)} findings", flush=True)


if __name__ == "__main__":
    main()
