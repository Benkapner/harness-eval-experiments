#!/usr/bin/env python3
"""Scan a seeded random sample of the frame with harness-eval.

For each repository: shallow single-branch clone, record the resolved commit,
run `harness-eval harness-lint --format json` under a timeout, record the
component inventory and findings, delete the working copy. No third-party
content is retained. Resumable: repositories already in the results file are
skipped.

usage: scan.py [N_REPOS] [SEED] [--workers K] [--all] [--only FILE] [--channel PREFIX] [--rescan-stale]
               [--pinned RESULTS.jsonl[.gz]] [--results OUT.jsonl] [--max-file-bytes N]
  --all scans every frame entry in seeded order instead of a sample.
  --pinned FILE re-scans the repositories of an earlier results file at the
    commits it recorded (instrument comparison: same bytes, new scanner).
    Without it the clone is the current default branch (ecosystem drift).
  --results FILE writes to FILE instead of data/results.jsonl, so a rescan
    never overwrites the published 7.15.0 records.
  --retry-timeouts drops records whose status is timeout from --results and
    re-scans them (use with fewer workers and --lint-timeout 900).
  --max-file-bytes N is passed to harness-eval (default 50 MB here; the tool's
    own default of 10 MB fails a repository that bundles one large asset).
  Every record carries head_now, the remote HEAD at scan time, and an
  mcp_declarations block: a count of every MCP server declaration in the tree
  by transport and pin state, independent of any rule, so unpinned-package
  findings have a declaration-level denominator.
  --rescan-stale re-scans repositories whose recorded tool commit is not the
    current one and whose findings include a rule touched since (listed in
    STALE_RULES), so every finding in the results file comes from the same
    rule semantics. Records are replaced in place.
"""
from __future__ import annotations

import json
import os
import random
import re
import shutil
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data"
FRAME = DATA / "frame.jsonl"
RESULTS = DATA / "results.jsonl"
if "--results" in sys.argv:
    RESULTS = Path(sys.argv[sys.argv.index("--results") + 1])
PINNED: dict[str, str] | None = None   # full_name -> commit, when --pinned
if "--pinned" in sys.argv:
    import gzip as _gz
    _src = Path(sys.argv[sys.argv.index("--pinned") + 1])
    _open = _gz.open if _src.suffix == ".gz" else open
    with _open(_src, "rt", encoding="utf-8") as _fh:
        PINNED = {json.loads(l)["full_name"]: json.loads(l).get("commit") for l in _fh if l.strip()}
MAX_FILE_BYTES = int(sys.argv[sys.argv.index("--max-file-bytes") + 1]) if "--max-file-bytes" in sys.argv else 50_000_000
CLONE_TIMEOUT = 300


def _tool_commit() -> str | None:
    """Git commit of the installed harness-eval, when it is an editable checkout."""
    try:
        import harness_eval
        src = Path(harness_eval.__file__).resolve()
        for parent in src.parents:
            if (parent / ".git").exists():
                r = subprocess.run(["git", "-C", str(parent), "rev-parse", "HEAD"], capture_output=True, text=True)
                return r.stdout.strip() or None
    except Exception:  # noqa: BLE001
        return None
    return None


TOOL_COMMIT = _tool_commit()
# Rules whose semantics changed during the study run; a repository that fired
# any of them under an earlier tool commit is re-scanned.
STALE_RULES = {"agent/referenced-skills-exist", "command/references-nonexistent-skill"}
LINT_TIMEOUT = int(sys.argv[sys.argv.index("--lint-timeout") + 1]) if "--lint-timeout" in sys.argv else 180


def _load_frame() -> list[dict]:
    return [json.loads(line) for line in FRAME.read_text().splitlines() if line.strip()]


def _ensure_plain_results() -> None:
    """scan.py appends to the plain file; recover it from the shipped .gz when absent."""
    gz = RESULTS.with_suffix(".jsonl.gz")
    if "--results" not in sys.argv and not RESULTS.exists() and gz.exists():
        import gzip
        RESULTS.write_text(gzip.open(gz, "rt", encoding="utf-8").read())


def _done() -> set[str]:
    if not RESULTS.exists():
        return set()
    return {json.loads(line)["full_name"] for line in RESULTS.read_text().splitlines() if line.strip()}


def _inventory(report: dict) -> dict:
    insp = report.get("inspection", {})
    comps = {k: len(v) for k, v in insp.items() if isinstance(v, list) and v}
    return {
        "component_types": comps,
        "component_count": report.get("component_count", sum(comps.values())),
        "detected_tools": report.get("detected_tools", []),
        "budget": {k: report.get("budget", {}).get(k) for k in ("total_tokens", "always_loaded", "on_demand", "by_type")},
    }


def _findings(report: dict, clone_root: str = "") -> list[dict]:
    out = []
    for ctype, comps in report.get("inspection", {}).items():
        if not isinstance(comps, list):
            continue
        for c in comps:
            for f in c.get("findings", []):
                file = f.get("file") or ""
                if clone_root and file.startswith(clone_root):
                    file = file[len(clone_root):].lstrip("/")
                out.append({"rule": f.get("rule"), "severity": f.get("severity"),
                            "component_type": ctype, "component": c.get("name"),
                            "file": file, "line": f.get("line"),
                            "message": (f.get("message") or "")[:400],
                            "data": f.get("data")})
    return out

_MCP_FILE_NAMES = {".mcp.json", "mcp.json", "settings.json", "claude_desktop_config.json", "mcp_config.json"}
_PKG_RUNNERS = {"npx", "bunx", "pnpx", "uvx", "pipx", "docker", "podman"}
_SKIP_DIRS = {"node_modules", ".git", "dist", "build", "vendor", "venv", ".venv", "target"}


def _strip_jsonc(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    text = re.sub(r"(^|[^:\\\"])//[^\n]*", r"\1", text)
    return re.sub(r",(\s*[}\]])", r"\1", text)


def _server_maps(data) -> list[dict]:
    """Every server map in a parsed config: mcpServers / servers, or a flat plugin-style map."""
    out = []
    if not isinstance(data, dict):
        return out
    for key in ("mcpServers", "servers", "mcp_servers"):
        if isinstance(data.get(key), dict):
            out.append(data[key])
    if not out and data and all(isinstance(v, dict) and ("command" in v or "url" in v or "httpUrl" in v) for v in data.values()):
        out.append(data)
    return out


def _classify_server(spec: dict) -> tuple[str, str]:
    """(transport, pin) for one declaration. transport: remote | package | local | other.
    pin: pinned | unpinned | tag | n/a. Written against the npx/uvx/docker argument
    grammars, independently of the scanner's rule."""
    if any(k in spec for k in ("url", "httpUrl", "serverUrl")):
        return "remote", "n/a"
    cmd = spec.get("command")
    if not isinstance(cmd, str) or not cmd.strip():
        return "other", "n/a"
    base = cmd.strip().replace("\\", "/").rsplit("/", 1)[-1].lower()
    args = [a for a in (spec.get("args") or []) if isinstance(a, str)]
    if base in ("npx", "bunx", "pnpx"):
        pkg = next((a for a in args if not a.startswith("-") and a not in ("-y", "--yes")), None)
        if pkg is None:
            return "package", "unpinned"
        name_part = pkg[1:] if pkg.startswith("@") else pkg
        if "@" in name_part:
            ver = name_part.rsplit("@", 1)[1]
            if ver in ("latest", "next", "canary", "beta", "alpha", "") or ver.startswith(("^", "~", ">", "<", "*")):
                return "package", "tag"
            return "package", "pinned"
        return "package", "unpinned"
    if base in ("uvx", "pipx"):
        if "--from" in args:
            i = args.index("--from")
            spec_s = args[i + 1] if i + 1 < len(args) else ""
        else:
            spec_s = next((a for a in args if not a.startswith("-")), "")
        if "==" in spec_s or re.search(r"@[0-9a-f]{7,40}$|@v?\d", spec_s):
            return "package", "pinned"
        if spec_s.startswith("git+") or "://" in spec_s:
            return "package", "unpinned"
        return "package", "unpinned"
    if base in ("docker", "podman"):
        image = None
        skip_next = False
        for a in args[1:] if args and args[0] in ("run", "create") else args:
            if skip_next:
                skip_next = False
                continue
            if a.startswith("-"):
                if a in ("-e", "--env", "-v", "--volume", "--mount", "-p", "--publish", "--name", "--network", "--pull",
                         "--restart", "--cap-drop", "--cap-add", "--security-opt", "-w", "--workdir", "--entrypoint", "-u", "--user", "--platform"):
                    skip_next = True
                continue
            image = a
            break
        if image is None:
            return "package", "unpinned"
        if "@sha256:" in image:
            return "package", "pinned"
        tag = image.rsplit(":", 1)[1] if ":" in image.rsplit("/", 1)[-1] else None
        if tag is None or tag == "latest":
            return "package", "tag" if tag == "latest" else "unpinned"
        return "package", "pinned"
    return "local", "n/a"


def _mcp_declarations(root: Path) -> dict:
    counts = {"files": 0, "total": 0, "remote": 0, "package": 0, "local": 0, "other": 0,
              "package_pinned": 0, "package_unpinned": 0, "package_tag": 0}
    seen = set()
    for p in root.rglob("*"):
        if not p.is_file() or p.name not in _MCP_FILE_NAMES:
            continue
        if any(part in _SKIP_DIRS for part in p.relative_to(root).parts):
            continue
        if p.name == "settings.json" and p.parent.name not in (".gemini", ".claude", ".vscode"):
            continue
        try:
            if p.stat().st_size > 2_000_000:
                continue
            data = json.loads(_strip_jsonc(p.read_text(encoding="utf-8", errors="replace")))
        except (OSError, ValueError):
            continue
        maps = _server_maps(data)
        if not maps:
            continue
        counts["files"] += 1
        for m in maps:
            for name, spec in m.items():
                if not isinstance(spec, dict) or spec.get("disabled") is True:
                    continue
                key = (p.relative_to(root).as_posix(), name)
                if key in seen:
                    continue
                seen.add(key)
                transport, pin = _classify_server(spec)
                counts["total"] += 1
                counts[transport] += 1
                if transport == "package":
                    counts[f"package_{pin}"] += 1
    return counts


def scan_one(entry: dict) -> dict:
    fn = entry["full_name"]
    t0 = time.time()
    rec: dict = {"full_name": fn, "url": f"https://github.com/{fn}", "channels": entry.get("channels", []),
                 "stars": entry.get("stars", 0), "scanned_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    tmp = tempfile.mkdtemp(prefix="he-")
    try:
        dest = Path(tmp) / "repo"
        env = dict(os.environ, GIT_TERMINAL_PROMPT="0")
        pinned_sha = PINNED.get(fn) if PINNED is not None else None
        if PINNED is not None and not pinned_sha:
            rec["status"] = "no_pinned_commit"
            return rec
        if pinned_sha:
            # Same bytes the earlier scan saw: fetch exactly that commit.
            subprocess.run(["git", "init", "-q", str(dest)], check=True, capture_output=True, env=env)
            subprocess.run(["git", "-C", str(dest), "remote", "add", "origin", f"https://github.com/{fn}.git"],
                           check=True, capture_output=True, env=env)
            cp = subprocess.run(["git", "-C", str(dest), "fetch", "-q", "--depth", "1", "origin", pinned_sha],
                                capture_output=True, text=True, timeout=CLONE_TIMEOUT, env=env)
            if cp.returncode == 0:
                cp = subprocess.run(["git", "-C", str(dest), "checkout", "-q", "FETCH_HEAD"],
                                    capture_output=True, text=True, timeout=CLONE_TIMEOUT, env=env)
        else:
            cp = subprocess.run(["git", "clone", "--depth", "1", "--single-branch", "--quiet",
                                 f"https://github.com/{fn}.git", str(dest)],
                                capture_output=True, text=True, timeout=CLONE_TIMEOUT, env=env)
        if cp.returncode != 0:
            rec["status"] = "clone_failed"
            rec["error"] = cp.stderr.strip()[-200:]
            return rec
        sha = subprocess.run(["git", "-C", str(dest), "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
        rec["commit"] = sha
        rec["pinned"] = bool(pinned_sha)
        try:
            ls = subprocess.run(["git", "ls-remote", f"https://github.com/{fn}.git", "HEAD"],
                                capture_output=True, text=True, timeout=60, env=env)
            rec["head_now"] = ls.stdout.split()[0] if ls.stdout.strip() else None
        except subprocess.TimeoutExpired:
            rec["head_now"] = None
        rec["mcp_declarations"] = _mcp_declarations(dest)
        # Presence of files the tool does not itself inventory but the study reports on.
        rec["files"] = {
            "settings_local": (dest / ".claude" / "settings.local.json").is_file(),
            "settings": (dest / ".claude" / "settings.json").is_file(),
            "mcp_json": (dest / ".mcp.json").is_file(),
            "claude_md": (dest / "CLAUDE.md").is_file(),
            "agents_md": (dest / "AGENTS.md").is_file(),
            "gemini_md": (dest / "GEMINI.md").is_file(),
            "cursorrules": (dest / ".cursorrules").is_file() or (dest / ".cursor" / "rules").is_dir(),
            "copilot": (dest / ".github" / "copilot-instructions.md").is_file(),
            "claude_skills": (dest / ".claude" / "skills").is_dir(),
            "claude_agents": (dest / ".claude" / "agents").is_dir(),
            "claude_commands": (dest / ".claude" / "commands").is_dir(),
        }
        lp = subprocess.run(["harness-eval", "harness-lint", str(dest), "--all", "--format", "json", "--enforce", "advisory",
                             "--max-file-bytes", str(MAX_FILE_BYTES)],
                            capture_output=True, text=True, timeout=LINT_TIMEOUT, cwd=str(dest))
        out = lp.stdout
        start = out.find("{")
        if start < 0:
            rec["status"] = "lint_failed"
            rec["error"] = (lp.stderr or out)[-300:]
            return rec
        try:
            report = json.loads(out[start:])
        except json.JSONDecodeError as e:
            rec["status"] = "lint_failed"
            rec["error"] = f"json: {e}"
            return rec
        rec["status"] = "ok"
        rec["tool_version"] = report.get("metadata", {}).get("version")
        rec["tool_commit"] = TOOL_COMMIT
        rec["inventory"] = _inventory(report)
        rec["findings"] = _findings(report, str(dest.resolve()))
        rec["rules_checked"] = report.get("metadata", {}).get("rules_checked")
        return rec
    except subprocess.TimeoutExpired:
        rec["status"] = "timeout"
        return rec
    except Exception as e:  # noqa: BLE001
        rec["status"] = "error"
        rec["error"] = str(e)[:200]
        return rec
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
        rec["duration_s"] = round(time.time() - t0, 2)


def main() -> None:
    _ensure_plain_results()
    argv = sys.argv[1:]
    skip = {argv[i + 1] for i, a in enumerate(argv)
            if a in ("--workers", "--channel", "--only", "--pinned", "--results", "--max-file-bytes", "--lint-timeout") and i + 1 < len(argv)}
    args = [a for a in argv if not a.startswith("--") and a not in skip]
    n = int(args[0]) if args else 400
    seed = int(args[1]) if len(args) > 1 else 255
    workers = 6
    if "--workers" in sys.argv:
        workers = int(sys.argv[sys.argv.index("--workers") + 1])
    frame = _load_frame()
    if PINNED is not None:
        by_name = {e["full_name"]: e for e in frame}
        frame = [by_name.get(fn, {"full_name": fn, "channels": [], "stars": 0}) for fn in PINNED]
    rng = random.Random(seed)
    order = frame[:]
    rng.shuffle(order)
    if "--channel" in sys.argv:
        prefix = sys.argv[sys.argv.index("--channel") + 1]
        order = [e for e in frame if any(c.startswith(prefix) for c in e.get("channels", []))]
    elif "--only" in sys.argv:
        # scan exactly the repositories listed in a file (one full_name per line)
        wanted = {l.strip() for l in open(sys.argv[sys.argv.index("--only") + 1]) if l.strip()}
        order = [e for e in frame if e["full_name"] in wanted]
    elif "--all" not in sys.argv:
        order = order[:n]
    if "--retry-timeouts" in sys.argv and RESULTS.exists():
        recs = [json.loads(l) for l in RESULTS.read_text().splitlines() if l.strip()]
        retry = {r["full_name"] for r in recs if r.get("status") in ("timeout", "error")}
        RESULTS.write_text("".join(json.dumps(r) + "\n" for r in recs if r["full_name"] not in retry))
        print(f"re-scanning {len(retry)} timed-out repositories", file=sys.stderr, flush=True)
    if "--rescan-stale" in sys.argv:
        recs = [json.loads(l) for l in RESULTS.read_text().splitlines() if l.strip()]
        stale = {r["full_name"] for r in recs if r.get("status") == "ok" and r.get("tool_commit") != TOOL_COMMIT
                 and any(f["rule"] in STALE_RULES for f in r.get("findings", []))}
        keep = [r for r in recs if r["full_name"] not in stale]
        RESULTS.write_text("".join(json.dumps(r) + "\n" for r in keep))
        order = [e for e in frame if e["full_name"] in stale]
        print(f"re-scanning {len(order)} stale repositories", file=sys.stderr, flush=True)
    done = _done()
    todo = [e for e in order if e["full_name"] not in done]
    print(f"frame {len(frame)}, sample {len(order)}, done {len(done)}, todo {len(todo)}", file=sys.stderr, flush=True)
    with RESULTS.open("a") as f, ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(scan_one, e): e for e in todo}
        for i, fut in enumerate(as_completed(futs), 1):
            rec = fut.result()
            f.write(json.dumps(rec) + "\n")
            f.flush()
            if i % 10 == 0:
                print(f"  {i}/{len(todo)} last={rec['full_name']} {rec['status']}", file=sys.stderr, flush=True)


if __name__ == "__main__":
    main()
