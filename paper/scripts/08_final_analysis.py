#!/usr/bin/env python3
"""Final analysis: harness defects across the setup population, using the
calibrated rule set (v7.10.1).

Reports characterization of real setups, defect prevalence by category, and the
scope ablation separating findings reachable by single-file analysis from those
that are not.
"""
from __future__ import annotations
import json, math, pathlib, statistics as st
from collections import Counter, defaultdict

DATA = pathlib.Path(__file__).resolve().parent.parent / "data"
RES = [json.loads(l) for l in (DATA / "results_fixed.jsonl").open() if l.strip()]
OK = [r for r in RES if r.get("status") == "ok"]
SCOPE = {r["rule_id"]: r["scope"] for r in json.load((DATA / "rule_scope.json").open())}
SETUPS = [r for r in OK if r["klass"] == "SETUP"]
COLL = [r for r in OK if r["klass"] == "COLLECTION"]


def pct(a, b):
    return round(100.0 * a / b, 1) if b else 0.0


def wilson(k, n, z=1.96):
    if not n:
        return (0.0, 0.0)
    p, d = k / n, 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (max(0.0, c - h), min(1.0, c + h))


def has(rs, pred):
    return sum(1 for r in rs if any(pred(f) for f in r.get("findings", [])))


out = {}
out["population"] = {"setups": len(SETUPS), "collections": len(COLL),
                     "scanned": len(RES), "ok": len(OK)}

for label, rs in (("SETUP", SETUPS), ("COLLECTION", COLL)):
    comps = [r.get("component_count", 0) for r in rs]
    toks = [(r.get("budget") or {}).get("total_tokens", 0) for r in rs]
    always = [(r.get("budget") or {}).get("always_loaded", 0) for r in rs]
    beyond = has(rs, lambda f: SCOPE.get(f["rule_id"]) in ("FILE_FS", "PAIRWISE", "SETUP"))
    setupscope = has(rs, lambda f: SCOPE.get(f["rule_id"]) == "SETUP")
    setup_no_orphan = has(rs, lambda f: SCOPE.get(f["rule_id"]) == "SETUP"
                          and f["rule_id"] != "content/orphan-skills")
    sec = has(rs, lambda f: f["rule_id"].startswith("security/"))
    err = has(rs, lambda f: f.get("severity") == "error")
    n = len(rs)
    lo, hi = wilson(beyond, n)
    out[label] = {
        "n": n,
        "components_median": int(st.median(comps)) if comps else 0,
        "components_max": max(comps) if comps else 0,
        "tokens_median": int(st.median(toks)) if toks else 0,
        "tokens_max": max(toks) if toks else 0,
        "always_loaded_median": int(st.median(always)) if always else 0,
        "any_finding_pct": pct(has(rs, lambda f: True), n),
        "error_severity_pct": pct(err, n),
        "security_pct": pct(sec, n),
        "beyond_file_pct": pct(beyond, n),
        "beyond_file_ci": [round(100 * lo, 1), round(100 * hi, 1)],
        "setup_scope_pct": pct(setupscope, n),
        "setup_scope_excl_orphan_pct": pct(setup_no_orphan, n),
        "multi_assistant_pct": pct(sum(1 for r in rs if len(r.get("detected_tools", [])) > 1), n),
        "findings_total": sum(len(r.get("findings", [])) for r in rs),
    }

# scope ablation over findings volume, setups only
c = Counter()
for r in SETUPS:
    for f in r.get("findings", []):
        s = SCOPE.get(f["rule_id"])
        if s:
            c[s] += 1
out["ablation_setups"] = dict(c)
out["ablation_beyond_file_pct"] = pct(sum(v for k, v in c.items() if k != "FILE"), sum(c.values()))

# per-rule, setups only
rc, rr = Counter(), defaultdict(set)
for r in SETUPS:
    for f in r.get("findings", []):
        rc[f["rule_id"]] += 1
        rr[f["rule_id"]].add(r["full_name"])
out["top_rules_setups"] = [
    {"rule": k, "findings": v, "repos": len(rr[k]),
     "repo_pct": pct(len(rr[k]), len(SETUPS)), "scope": SCOPE.get(k)}
    for k, v in rc.most_common(15)]
out["setup_scope_rules"] = [
    {"rule": k, "repos": len(rr[k]), "repo_pct": pct(len(rr[k]), len(SETUPS))}
    for k, v in rc.most_common() if SCOPE.get(k) == "SETUP"]

# tools
tc = Counter()
for r in OK:
    for t in r.get("detected_tools", []):
        tc[t] += 1
out["tools"] = dict(tc.most_common())

(DATA / "analysis_final.json").write_text(json.dumps(out, indent=1))

print(json.dumps({k: v for k, v in out.items()
                  if k not in ("top_rules_setups", "setup_scope_rules")}, indent=1))
print("\nTOP RULES (setups)")
for r in out["top_rules_setups"]:
    print(f'  {r["scope"]:9} {r["rule"]:42} {r["repos"]:4} repos {r["repo_pct"]:5}%')
print("\nSETUP-SCOPE RULES (setups)")
for r in out["setup_scope_rules"]:
    print(f'  {r["rule"]:42} {r["repos"]:4} repos {r["repo_pct"]:5}%')
