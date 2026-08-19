#!/usr/bin/env python3
"""Regenerate every number cited in the paper, labelled by the section that
cites it. If a number appears in the paper and not in this output, it does not
belong in the paper.

Usage:  python scripts/verify_claims.py [--json]
"""
from __future__ import annotations
import json, pathlib, statistics as st, sys
from collections import Counter, defaultdict

DATA = pathlib.Path(__file__).resolve().parent.parent / "data"
RES = [json.loads(l) for l in (DATA / "results.jsonl").open() if l.strip()]
SCOPE = {r["rule_id"]: r["scope"] for r in json.load((DATA / "rule_scope.json").open())}
FRAME = sum(1 for _ in (DATA / "frame_candidates.jsonl").open())

COMPONENT_TYPES = {"skill", "command", "agent", "hooks", "mcp"}
BEYOND = {"FILE_FS", "PAIRWISE", "SETUP"}
claims: dict[str, object] = {}


def classify(r):
    cbt = r.get("components_by_type", {}) or {}
    present = {k for k, v in cbt.items() if v and k != "summary"}
    real = present & COMPONENT_TYPES
    ns, no = cbt.get("skill", 0), sum(cbt.get(k, 0) for k in ("command", "agent", "hooks", "mcp"))
    if not present:
        return "EMPTY"
    if not real:
        return "INSTRUCTION_ONLY"
    if ns >= 5 and no == 0:
        return "COLLECTION"
    if len(real) >= 2 or (real - {"skill"}):
        return "SETUP"
    return "COLLECTION" if ns >= 5 else "INSTRUCTION_ONLY"


OK = [r for r in RES if r.get("status") == "ok"]
for r in OK:
    r["klass"] = classify(r)


def pct(a, b):
    return round(100.0 * a / b, 1) if b else 0.0


def scope_counts(rs):
    c = Counter()
    for r in rs:
        for f in r.get("findings", []):
            c[SCOPE.get(f["rule_id"], "UNKNOWN")] += 1
    return c


def n_with(rs, scopes, exclude=()):
    n = 0
    for r in rs:
        if any(SCOPE.get(f["rule_id"]) in scopes and f["rule_id"] not in exclude
               for f in r.get("findings", [])):
            n += 1
    return n


# --- Section IV: rule set -----------------------------------------------
sc = Counter(v for v in SCOPE.values())
claims["IV.rules_total"] = len(SCOPE)
claims["IV.rules_by_scope"] = dict(sc)
claims["IV.rules_beyond_file"] = sum(v for k, v in sc.items() if k != "FILE")
claims["IV.rules_beyond_file_pct"] = pct(claims["IV.rules_beyond_file"], len(SCOPE))
claims["IV.rules_manually_corrected"] = sum(
    1 for r in json.load((DATA / "rule_scope.json").open()) if r.get("manually_corrected"))

# --- Section V: study design --------------------------------------------
claims["V.frame_size"] = FRAME
claims["V.scanned"] = len(RES)
claims["V.status"] = dict(Counter(r.get("status") for r in RES))
secs = [r["scan_seconds"] for r in OK if r.get("scan_seconds")]
claims["V.scan_seconds_median"] = round(st.median(secs), 1) if secs else 0

# --- Section VI RQ1 ------------------------------------------------------
kc = Counter(r["klass"] for r in OK)
claims["VI.RQ1.classes"] = dict(kc)
claims["VI.RQ1.classes_pct"] = {k: pct(v, len(OK)) for k, v in kc.items()}
setups = [r for r in OK if r["klass"] == "SETUP"]
comps = [r.get("component_count", 0) for r in setups]
toks = [(r.get("budget") or {}).get("total_tokens", 0) for r in setups]
always = [(r.get("budget") or {}).get("always_loaded", 0) for r in setups]
claims["VI.RQ1.setup_components_median"] = int(st.median(comps))
claims["VI.RQ1.setup_components_max"] = max(comps)
claims["VI.RQ1.setup_tokens_median"] = int(st.median(toks))
claims["VI.RQ1.setup_tokens_max"] = max(toks)
claims["VI.RQ1.setup_always_loaded_median"] = int(st.median(always))
tc = Counter()
for r in OK:
    for t in r.get("detected_tools", []):
        tc[t] += 1
claims["VI.RQ1.tools"] = dict(tc.most_common())
claims["VI.RQ1.multi_tool_pct"] = pct(sum(1 for r in OK if len(r.get("detected_tools", [])) > 1), len(OK))

# --- Section VI RQ2 ------------------------------------------------------
for name in ("SETUP", "COLLECTION", "INSTRUCTION_ONLY"):
    rs = [r for r in OK if r["klass"] == name]
    claims[f"VI.RQ2.{name}.n"] = len(rs)
    claims[f"VI.RQ2.{name}.any_finding_pct"] = pct(sum(1 for r in rs if r.get("findings")), len(rs))
claims["VI.RQ2.all_any_finding_pct"] = pct(sum(1 for r in OK if r.get("findings")), len(OK))
SECPREFIX = ("security/",)
claims["VI.RQ2.security_repos_pct"] = pct(
    sum(1 for r in OK if any(f["rule_id"].startswith(SECPREFIX) for f in r.get("findings", []))), len(OK))
rc, rr = Counter(), defaultdict(set)
for r in OK:
    for f in r.get("findings", []):
        rc[f["rule_id"]] += 1
        rr[f["rule_id"]].add(r["full_name"])
claims["VI.RQ2.top_rules"] = [
    {"rule": k, "findings": v, "repos": len(rr[k]), "scope": SCOPE.get(k)}
    for k, v in rc.most_common(10)]

# --- Section VI RQ3: the ablation ---------------------------------------
for name in ("SETUP", "COLLECTION", "INSTRUCTION_ONLY"):
    rs = [r for r in OK if r["klass"] == name]
    c = scope_counts(rs)
    total = sum(c.values())
    beyond = sum(v for k, v in c.items() if k != "FILE")
    claims[f"VI.RQ3.{name}.findings_total"] = total
    claims[f"VI.RQ3.{name}.findings_beyond_file"] = beyond
    claims[f"VI.RQ3.{name}.findings_beyond_file_pct"] = pct(beyond, total)
    claims[f"VI.RQ3.{name}.repos_beyond_file_pct"] = pct(n_with(rs, BEYOND), len(rs))
    claims[f"VI.RQ3.{name}.repos_setup_scope_pct"] = pct(n_with(rs, {"SETUP"}), len(rs))
    claims[f"VI.RQ3.{name}.repos_setup_scope_excl_orphan_pct"] = pct(
        n_with(rs, {"SETUP"}, exclude={"content/orphan-skills"}), len(rs))
claims["VI.RQ3.orphan_skills_repos"] = len(rr["content/orphan-skills"])
claims["VI.RQ3.setup_scope_rule_repos"] = {
    k: len(rr[k]) for k in sorted(SCOPE) if SCOPE[k] == "SETUP" and k in rr}

# --- Section VI RQ4: audit census ---------------------------------------
RARE = {"security/cross-component-flow", "content/permission-escalation",
        "cross/overpermissive-grants", "content/mcp-skill-alignment",
        "content/circular-references", "cross/multi-assistant-drift"}
claims["VI.RQ4.census_repos"] = len({r["full_name"] for r in OK
                                     if any(f["rule_id"] in RARE for f in r.get("findings", []))})
claims["VI.RQ4.per_rule_repos"] = {k: len(rr[k]) for k in sorted(RARE) if k in rr}


def main():
    if "--json" in sys.argv:
        print(json.dumps(claims, indent=1))
        return
    for k, v in claims.items():
        if isinstance(v, (dict, list)):
            print(f"{k}:")
            if isinstance(v, dict):
                for kk, vv in v.items():
                    print(f"    {kk}: {vv}")
            else:
                for item in v:
                    print(f"    {item}")
        else:
            print(f"{k}: {v}")


if __name__ == "__main__":
    main()
