#!/usr/bin/env python3
"""Analyse the scanned corpus: classify repos, compute prevalence and the
single-file vs full-setup scope ablation. All paper numbers come from here."""
from __future__ import annotations
import json, pathlib, statistics as st
from collections import Counter, defaultdict

HERE = pathlib.Path(__file__).resolve().parent.parent / "data"
RES = [json.loads(l) for l in (HERE / "results.jsonl").open() if l.strip()]
SCOPE = {r["rule_id"]: r["scope"] for r in json.load((HERE / "rule_scope.json").open())}

OK = [r for r in RES if r.get("status") == "ok"]

INSTRUCTION_TYPES = {"claude_md", "context_file", "uncategorized"}
COMPONENT_TYPES = {"skill", "command", "agent", "hooks", "mcp"}


def classify(r: dict) -> str:
    """SETUP / COLLECTION / INSTRUCTION_ONLY / EMPTY"""
    cbt = r.get("components_by_type", {}) or {}
    present = {k for k, v in cbt.items() if v and k != "summary"}
    real = present & COMPONENT_TYPES
    n_skill = cbt.get("skill", 0)
    n_other = sum(cbt.get(k, 0) for k in ("command", "agent", "hooks", "mcp"))
    if not present:
        return "EMPTY"
    if not real:
        return "INSTRUCTION_ONLY"
    # a collection publishes many skills and almost nothing that composes them
    if n_skill >= 5 and n_other == 0:
        return "COLLECTION"
    if len(real) >= 2 or (real - {"skill"}):
        return "SETUP"
    return "COLLECTION" if n_skill >= 5 else "INSTRUCTION_ONLY"


for r in OK:
    r["klass"] = classify(r)


def findings_by_scope(rs):
    c = Counter()
    for r in rs:
        for f in r.get("findings", []):
            c[SCOPE.get(f["rule_id"], "UNKNOWN")] += 1
    return c


def repos_with_scope(rs, scopes):
    n = 0
    for r in rs:
        if any(SCOPE.get(f["rule_id"]) in scopes for f in r.get("findings", [])):
            n += 1
    return n


def pct(a, b):
    return 0.0 if not b else round(100.0 * a / b, 1)


out = {}
out["scanned"] = len(RES)
out["status"] = dict(Counter(r.get("status") for r in RES))
out["classes"] = dict(Counter(r["klass"] for r in OK))

for klass in ("SETUP", "COLLECTION", "INSTRUCTION_ONLY", "ALL"):
    rs = OK if klass == "ALL" else [r for r in OK if r["klass"] == klass]
    if not rs:
        continue
    comps = [r.get("component_count", 0) for r in rs]
    toks = [(r.get("budget") or {}).get("total_tokens", 0) for r in rs]
    always = [(r.get("budget") or {}).get("always_loaded", 0) for r in rs]
    fsc = findings_by_scope(rs)
    beyond = sum(v for k, v in fsc.items() if k != "FILE")
    total = sum(fsc.values())
    d = {
        "n": len(rs),
        "components_median": int(st.median(comps)) if comps else 0,
        "components_max": max(comps) if comps else 0,
        "tokens_median": int(st.median(toks)) if toks else 0,
        "tokens_max": max(toks) if toks else 0,
        "always_loaded_median": int(st.median(always)) if always else 0,
        "repos_with_any_finding": sum(1 for r in rs if r.get("findings")),
        "repos_with_any_finding_pct": pct(sum(1 for r in rs if r.get("findings")), len(rs)),
        "findings_total": total,
        "findings_by_scope": dict(fsc),
        "findings_beyond_file": beyond,
        "findings_beyond_file_pct": pct(beyond, total),
        "repos_with_beyond_file": repos_with_scope(rs, {"FILE_FS", "PAIRWISE", "SETUP"}),
        "repos_with_beyond_file_pct": pct(repos_with_scope(rs, {"FILE_FS", "PAIRWISE", "SETUP"}), len(rs)),
        "repos_with_setup_scope": repos_with_scope(rs, {"SETUP"}),
        "repos_with_setup_scope_pct": pct(repos_with_scope(rs, {"SETUP"}), len(rs)),
        "multi_tool_repos": sum(1 for r in rs if len(r.get("detected_tools", [])) > 1),
    }
    out[klass] = d

# most prevalent rules, overall and setup-scope only
rc = Counter()
rc_repos = defaultdict(set)
for r in OK:
    for f in r.get("findings", []):
        rc[f["rule_id"]] += 1
        rc_repos[f["rule_id"]].add(r["full_name"])
out["top_rules"] = [
    {"rule_id": k, "findings": v, "repos": len(rc_repos[k]),
     "repo_pct": pct(len(rc_repos[k]), len(OK)), "scope": SCOPE.get(k, "?")}
    for k, v in rc.most_common(25)
]
out["top_setup_rules"] = [
    {"rule_id": k, "findings": v, "repos": len(rc_repos[k]),
     "repo_pct": pct(len(rc_repos[k]), len(OK))}
    for k, v in rc.most_common() if SCOPE.get(k) == "SETUP"
][:15]

# security-category subset
SEC = {k for k in SCOPE if k.split("/")[0] in ("security",) or "credential" in k
       or "injection" in k or "exfiltration" in k}
out["security_repos"] = sum(1 for r in OK if any(f["rule_id"] in SEC for f in r.get("findings", [])))
out["security_repos_pct"] = pct(out["security_repos"], len(OK))

# tools
tc = Counter()
for r in OK:
    for t in r.get("detected_tools", []):
        tc[t] += 1
out["tools"] = dict(tc.most_common())
out["multi_tool_pct"] = pct(sum(1 for r in OK if len(r.get("detected_tools", [])) > 1), len(OK))

# cost
secs = [r.get("scan_seconds", 0) for r in OK if r.get("scan_seconds")]
out["scan_seconds_median"] = round(st.median(secs), 2) if secs else 0

(HERE / "analysis.json").write_text(json.dumps(out, indent=1))
print(json.dumps({k: v for k, v in out.items() if k not in ("top_rules", "top_setup_rules")}, indent=1))
print("\nTOP RULES")
for r in out["top_rules"][:18]:
    print(f'  {r["scope"]:9} {r["rule_id"]:42} {r["findings"]:5}f {r["repos"]:4}repos {r["repo_pct"]}%')
print("\nTOP SETUP-SCOPE RULES")
for r in out["top_setup_rules"]:
    print(f'  {r["rule_id"]:42} {r["findings"]:5}f {r["repos"]:4}repos {r["repo_pct"]}%')
