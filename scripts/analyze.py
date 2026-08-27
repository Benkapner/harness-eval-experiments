#!/usr/bin/env python3
"""Compute every number reported in the paper from data/results.jsonl.

Outputs:
  data/summary.json          all statistics, machine-readable
  data/manifest.jsonl        one line per scanned repo: url, commit, stratum, per-scope finding counts
  paper/numbers.tex          \\newcommand macros consumed by the paper (no hand-typed numbers)
  paper/tables_generated.tex Table 2 (defects by rule and stratum) and Table 3 (audited precision)
  figures/results.png        headline and per-rule prevalence figure

Strata (assigned from the tool's own component inventory):
  SETUP             two or more component types, or any non-instruction component
  COLLECTION        five or more skills and no component that composes them
  INSTRUCTION_ONLY  one or more context/instruction files and nothing else
  EMPTY             the tool found no harness component
"""
from __future__ import annotations

import json
import re
import math
import statistics
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data"
RESULTS = DATA / "results.jsonl"
SCOPE = DATA / "rule_scope.json"
AUDIT = DATA / "audit_summary.json"
PAPER = ROOT / "paper"
FIG = ROOT / "figures"
PAPER.mkdir(exist_ok=True)
FIG.mkdir(exist_ok=True)

# The tool reports every instruction artifact (CLAUDE.md, AGENTS.md, GEMINI.md,
# .cursorrules, .cursor/rules/*.mdc, copilot-instructions.md) under one
# inventory key. Files it discovers but cannot type are "uncategorized" and are
# excluded from stratification, as the paper states.
INSTRUCTION_TYPES = {"claude_md"}
IGNORED_TYPES = {"uncategorized"}

# Rules whose findings enter prevalence figures, with display name and family.
# A rule is in the reported set only if the audit (audit.py) confirms it at
# the paper's threshold; analyze.py reads that verdict from audit_summary.json
# and drops any rule below the bar.
CANDIDATE_RULES = {
    "frontmatter/unparseable": ("Frontmatter blocks loading", "Q"),
    "frontmatter/name-mismatch": ("Frontmatter name mismatch (tolerated)", "D"),
    "content/hardcoded-machine-path": ("Hardcoded machine path", "Q"),
    "mcp/unpinned-package": ("Unpinned MCP package", "S"),
    "content/circular-references": ("Circular reference chain", "C"),
    "cross/overpermissive-grants": ("Over-permissive grant", "S"),
    "cross/multi-assistant-drift": ("Cross-assistant divergence", "C"),
    "content/mcp-skill-alignment": ("MCP consumer mismatch", "C"),
    "agent/description-required": ("Missing agent description", "Q"),
    "hooks/permission-contradiction": ("Permission contradiction", "C"),
    "hooks/permission-prompt-disabled": ("Permission prompt disabled", "S"),
    "hooks/local-settings-committed": ("Local settings committed", "S"),
    "mcp/cross-assistant-divergence": ("MCP cross-assistant divergence", "C"),
    "mcp/json-duplicate-keys": ("Duplicate key in MCP config", "Q"),
    "hooks/json-duplicate-keys": ("Duplicate key in settings", "Q"),
    "claude-md/include-exists": ("Broken @import in context file", "Q"),
    "hooks/command-script-exists": ("Hook script missing", "Q"),
    "mcp/endpoint-integrity": ("MCP endpoint integrity", "S"),
    "security/credential-file-present": ("Secret file committed in skill", "S"),
    "structural/symlink-escape": ("Symlink escaping the repository", "S"),
}

# Illustrative, anonymized example per rule for the examples table (LaTeX).
EXAMPLES = {
    "frontmatter/format-valid": r"\texttt{name: my-skill} inside \texttt{skills/myskill/}, or no \texttt{---} block at all",
    "content/hardcoded-machine-path": r"\texttt{/Users/evan/projects/\ldots} or \texttt{C:\textbackslash Users\textbackslash\ldots} in a skill file",
    "mcp/unpinned-package": r"\texttt{npx -y @modelcontextprotocol/server-filesystem}, no version",
    "content/circular-references": r"skill A: \texttt{invoke /b}; skill B: \texttt{invoke /a}",
    "cross/overpermissive-grants": r"\texttt{Bash(awk:*)}, \texttt{Bash(python:*)}, \texttt{Bash(find:*)} in \texttt{permissions.allow}",
    "cross/multi-assistant-drift": r"\texttt{CLAUDE.md} and \texttt{AGENTS.md} share most sections; one was edited",
    "content/mcp-skill-alignment": r"server declared in \texttt{.mcp.json}; no component names it",
    "agent/description-required": r"subagent file with no \texttt{description}; it can never be delegated to",
    "hooks/permission-contradiction": r"\texttt{allow: Bash(git commit:*)} with \texttt{deny: Bash(git:*)}",
    "hooks/permission-prompt-disabled": r"\texttt{defaultMode: bypassPermissions} committed in project settings",
    "hooks/local-settings-committed": r"\texttt{.claude/settings.local.json} in the tree",
    "mcp/cross-assistant-divergence": r"same server pinned in \texttt{.mcp.json}, unpinned in \texttt{.cursor/mcp.json}",
    "mcp/json-duplicate-keys": r"two \texttt{github} servers in one \texttt{.mcp.json}; the first is silently dropped",
    "hooks/json-duplicate-keys": r"two \texttt{permissions} blocks in \texttt{settings.json}",
    "claude-md/include-exists": r"\texttt{@docs/standards.md} in \texttt{CLAUDE.md}; no such file",
    "hooks/command-script-exists": r"hook runs \texttt{\$CLAUDE\_PROJECT\_DIR/.ai/start.py}; not committed",
    "mcp/endpoint-integrity": r"\texttt{url: http://host/sse} or \texttt{https://user:token@host}",
    "security/credential-file-present": r"\texttt{.env} or \texttt{*.pem} committed inside a skill",
    "structural/symlink-escape": r"\texttt{scripts/run.sh -> /tmp/\ldots}",
}
REFERENCE_RULE = "content/broken-references"
WITHDRAWN = {"content/orphan-skills", "command/references-nonexistent-skill", "security/cross-component-flow"}


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float, float]:
    if n == 0:
        return 0.0, 0.0, 0.0
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return 100 * p, 100 * max(0.0, c - h), 100 * min(1.0, c + h)


def stratum(rec: dict) -> str:
    inv = rec.get("inventory", {})
    types = {k: v for k, v in inv.get("component_types", {}).items() if v and k not in IGNORED_TYPES}
    if not types:
        return "EMPTY"
    skills = types.get("skill", 0)
    non_instruction = set(types) - INSTRUCTION_TYPES
    # A collection is a published set of skills with nothing that composes them;
    # a context file alone does not compose, since collections carry one for contributors.
    if skills >= 5 and non_instruction <= {"skill"}:
        return "COLLECTION"
    if len(types) >= 2 or non_instruction:
        return "SETUP"
    return "INSTRUCTION_ONLY"


def main() -> None:
    scope = json.loads(SCOPE.read_text())
    audit = json.loads(AUDIT.read_text()) if AUDIT.exists() else {}
    recs = [json.loads(l) for l in RESULTS.read_text().splitlines() if l.strip()]
    # Split the frontmatter rule by consequence: a block that is missing, unparseable
    # or has no name blocks loading; a name that does not match the directory is a
    # specification deviation that clients tolerate. Same predicate, different defect.
    for r in recs:
        for f in r.get("findings", []):
            if f["rule"] == "frontmatter/format-valid":
                f["rule"] = ("frontmatter/name-mismatch" if "does not match" in f["message"]
                             else "frontmatter/unparseable")
    if "frontmatter/format-valid" in audit:
        a = audit.pop("frontmatter/format-valid")
        b = a.get("breakdown", {})
        nm = b.get("name_mismatch", 0)
        audit["frontmatter/name-mismatch"] = {"audited": nm, "confirmed": nm, "refuted": 0, "unverifiable": 0,
                                             "breakdown": {"name_mismatch": nm}}
        rest = a["audited"] - nm
        audit["frontmatter/unparseable"] = {"audited": rest, "confirmed": a["confirmed"] - nm, "refuted": a["refuted"],
                                            "unverifiable": a["unverifiable"],
                                            "breakdown": {k: v for k, v in b.items() if k != "name_mismatch"}}
    ok = [r for r in recs if r.get("status") == "ok"]
    status = Counter(r.get("status") for r in recs)

    reported = {}     # every rule that meets the precision bar (listed in tables)
    gating = {}       # >= 50 audited: carries headline figures
    provisional = {}  # 13-49 audited, zero false positives: listed, kept out of every headline union
    for rid, (name, fam) in CANDIDATE_RULES.items():
        a = audit.get(rid)
        if a is None:
            continue
        n, k = a["audited"], a["confirmed"]
        if n >= 50 and k / n >= 0.97:
            reported[rid] = (name, fam); gating[rid] = (name, fam)
        elif n >= 13 and k == n:
            reported[rid] = (name, fam); provisional[rid] = (name, fam)
    headline = {rid: v for rid, v in gating.items() if v[1] != "D"}

    strata = defaultdict(list)
    for r in ok:
        r["stratum"] = stratum(r)
        strata[r["stratum"]].append(r)

    def has(r: dict, rid: str) -> bool:
        return any(f["rule"] == rid for f in r.get("findings", []))

    def rate(rs: list, pred) -> tuple[int, int, tuple[float, float, float]]:
        k = sum(1 for r in rs if pred(r))
        return k, len(rs), wilson(k, len(rs))

    beyond = {rid for rid, v in scope.items() if v["scope"] != "FILE"}
    for pseudo in ("frontmatter/unparseable", "frontmatter/name-mismatch"):
        scope.setdefault(pseudo, dict(scope["frontmatter/format-valid"]))
    security_rules = {rid for rid, v in scope.items() if v["security"]}
    summary: dict = {"n_scanned": len(recs), "status": dict(status), "n_ok": len(ok),
                     "strata": {s: len(v) for s, v in strata.items()},
                     "reported_rules": {rid: {"name": n, "family": f, "tier": ("gating" if rid in gating else "provisional")} for rid, (n, f) in reported.items()},
                     "gating_rules": list(gating), "provisional_rules": list(provisional), "headline_rules": list(headline),
                     "rule_scope_counts": dict(Counter(v["scope"] for v in scope.values())),
                     "rules_total": len(scope), "rules_beyond_file": len(beyond),
                     "rules_hand_corrected": sum(1 for v in scope.values() if v["corrected"]),
                     "per_stratum": {}}

    for s, rs in strata.items():
        d: dict = {"n": len(rs)}
        d["any_raw"] = rate(rs, lambda r: bool(r.get("findings")))
        d["any_error_raw"] = rate(rs, lambda r: any(f["severity"] == "error" for f in r.get("findings", [])))
        d["any_security_raw"] = rate(rs, lambda r: any(f["rule"] in security_rules for f in r.get("findings", [])))
        d["any_confirmed"] = rate(rs, lambda r: any(has(r, rid) for rid in headline))
        d["any_reported"] = rate(rs, lambda r: any(has(r, rid) for rid in reported))
        d["confirmed_beyond_file"] = rate(rs, lambda r: any(has(r, rid) for rid in headline if rid in beyond))
        d["confirmed_security"] = rate(rs, lambda r: any(has(r, rid) for rid, (n, f) in headline.items() if f == "S"))
        d["confirmed_security_incl_provisional"] = rate(rs, lambda r: any(has(r, rid) for rid, (n, f) in reported.items() if f == "S"))
        d["tolerated_only"] = rate(rs, lambda r: any(has(r, rid) for rid, (n, f) in reported.items() if f == "D") and not any(has(r, rid) for rid in headline))
        d["reference_rule"] = rate(rs, lambda r: has(r, REFERENCE_RULE))
        integrity = {"mcp/json-duplicate-keys", "hooks/json-duplicate-keys", "claude-md/include-exists",
                     "hooks/command-script-exists", "mcp/endpoint-integrity", "security/credential-file-present",
                     "structural/symlink-escape"}
        d["integrity_any"] = rate(rs, lambda r: any(has(r, rid) for rid in integrity))
        d["per_rule"] = {rid: rate(rs, lambda r, rid=rid: has(r, rid)) for rid in CANDIDATE_RULES}
        d["multi_assistant"] = rate(rs, lambda r: len(r.get("inventory", {}).get("detected_tools", [])) > 1)
        comps = [r["inventory"]["component_count"] for r in rs if r.get("inventory")]
        toks = [r["inventory"]["budget"]["total_tokens"] or 0 for r in rs if r.get("inventory")]
        always = [r["inventory"]["budget"]["always_loaded"] or 0 for r in rs if r.get("inventory")]
        d["median_components"] = statistics.median(comps) if comps else 0
        d["max_components"] = max(comps) if comps else 0
        d["median_tokens"] = statistics.median(toks) if toks else 0
        d["max_tokens"] = max(toks) if toks else 0
        d["median_always_loaded"] = statistics.median(always) if always else 0
        sc = Counter()
        for r in rs:
            for f in r.get("findings", []):
                sc[scope.get(f["rule"], {}).get("scope", "FILE")] += 1
        d["findings_by_scope"] = dict(sc)
        tools = Counter(t for r in rs for t in r.get("inventory", {}).get("detected_tools", []))
        d["tools"] = dict(tools.most_common())
        durs = [r["duration_s"] for r in rs if r.get("duration_s")]
        d["median_duration_s"] = statistics.median(durs) if durs else 0
        d["p95_duration_s"] = sorted(durs)[int(0.95 * (len(durs) - 1))] if durs else 0
        summary["per_stratum"][s] = d

    # Discovery-channel check on setups: topic-only vs readme-only vs curated.
    setups = strata.get("SETUP", [])
    def chan(r, prefix):
        return any(c.startswith(prefix) for c in r.get("channels", []))
    summary["channel_check"] = {
        "topic_only": rate([r for r in setups if chan(r, "topic:") and not chan(r, "readme:") and not chan(r, "curated:")],
                           lambda r: any(has(r, rid) for rid in reported)),
        "readme_only": rate([r for r in setups if chan(r, "readme:") and not chan(r, "topic:") and not chan(r, "curated:")],
                            lambda r: any(has(r, rid) for rid in reported)),
        "curated": rate([r for r in ok if chan(r, "curated:")], lambda r: any(has(r, rid) for rid in reported)),
        "curated_n_by_stratum": dict(Counter(r["stratum"] for r in ok if chan(r, "curated:"))),
        "agents": rate([r for r in ok if chan(r, "agents:")], lambda r: any(has(r, rid) for rid in reported)),
        "agents_raw": rate([r for r in ok if chan(r, "agents:")], lambda r: bool(r.get("findings"))),
        "agents_with_components": sum(1 for r in ok if chan(r, "agents:") and r["stratum"] != "EMPTY"),
    }
    tools_all = Counter(t for r in ok for t in r.get("inventory", {}).get("detected_tools", []))
    summary["tool_ranking"] = tools_all.most_common(8)
    flow = [r for r in ok if any(f["rule"] == "security/cross-component-flow" and "exfiltration" in f["message"].lower()
                                  for f in r.get("findings", []))]
    summary["flow_repos"] = len(flow)
    summary["flow_repo_names"] = [r["full_name"] for r in flow]
    summary["audit"] = audit
    af = DATA / "audit_findings.jsonl"
    summary["audit_repos"] = len({json.loads(l)["repo"] for l in af.read_text().splitlines() if l.strip()}) if af.exists() else 0

    (DATA / "summary.json").write_text(json.dumps(summary, indent=1, default=float))
    with (DATA / "manifest.jsonl").open("w") as f:
        for r in recs:
            sc = Counter(scope.get(x["rule"], {}).get("scope", "FILE") for x in r.get("findings", []))
            rules = sorted({x["rule"] for x in r.get("findings", [])})
            f.write(json.dumps({"url": r["url"], "commit": r.get("commit"), "status": r.get("status"),
                                "stratum": r.get("stratum"), "channels": r.get("channels"),
                                "findings_by_scope": dict(sc), "rules_fired": rules}) + "\n")
    _write_tex(summary, scope)
    _write_fig(summary)
    print(json.dumps({k: summary[k] for k in ("n_scanned", "status", "n_ok", "strata")}), file=sys.stderr)
    for s, d in summary["per_stratum"].items():
        print(f"{s}: n={d['n']} any_confirmed={d['any_confirmed'][2][0]:.1f}% beyond={d['confirmed_beyond_file'][2][0]:.1f}%"
              f" raw={d['any_raw'][2][0]:.1f}% ref={d['reference_rule'][2][0]:.1f}%", file=sys.stderr)


def _m(name: str, val) -> str:
    if isinstance(val, float):
        val = f"{val:.1f}"
    return f"\\newcommand{{\\{name}}}{{{val}}}\n"


def _num(name: str, val) -> str:
    return _m(name, f"{val:,}" if isinstance(val, int) else val)


def _write_tex(s: dict, scope: dict) -> None:
    out = ["% Generated by scripts/analyze.py. Do not edit by hand.\n"]
    out.append(_num("nScanned", s["n_scanned"]))
    out.append(_num("nOk", s["n_ok"]))
    out.append(_num("nRules", s["rules_total"]))
    out.append(_num("nRulesBeyond", s["rules_beyond_file"]))
    out.append(_m("pctRulesBeyond", 100 * s["rules_beyond_file"] / s["rules_total"]))
    out.append(_num("nRulesCorrected", s["rules_hand_corrected"]))
    for k, v in s["rule_scope_counts"].items():
        out.append(_num("nRules" + k.replace("_", ""), v))
    out.append(_num("nReportedRules", len(s["reported_rules"])))
    out.append(_num("nGatingRules", len(s["gating_rules"])))
    out.append(_num("nHeadlineRules", len(s["headline_rules"])))
    out.append(_num("nProvisionalRules", len(s["provisional_rules"])))
    letters = {"SETUP": "Setup", "COLLECTION": "Coll", "INSTRUCTION_ONLY": "Instr", "EMPTY": "Empty"}
    for st in letters:
        if st not in s["per_stratum"]:
            L = letters[st]
            out.append(_num("n" + L, 0))
            for short in ("AnyRaw", "ErrRaw", "SecRaw", "Confirmed", "AnyReported", "Beyond", "ConfSec", "ConfSecProv", "ToleratedOnly", "RefRule", "Multi", "Integrity"):
                for m in ("", "Lo", "Hi"):
                    out.append(_m(L + short + m, 0.0))
                out.append(_num(L + short + "K", 0))
            for rid in CANDIDATE_RULES:
                key = "".join(w.capitalize() for w in rid.replace("/", "-").split("-"))
                for m in ("", "Lo", "Hi"):
                    out.append(_m(L + key + m, 0.0))
    for st, d in s["per_stratum"].items():
        L = letters[st]
        out.append(_num("n" + L, d["n"]))
        for key, short in [("any_raw", "AnyRaw"), ("any_error_raw", "ErrRaw"), ("any_security_raw", "SecRaw"),
                           ("any_confirmed", "Confirmed"), ("any_reported", "AnyReported"), ("confirmed_beyond_file", "Beyond"),
                           ("confirmed_security", "ConfSec"), ("confirmed_security_incl_provisional", "ConfSecProv"),
                           ("tolerated_only", "ToleratedOnly"), ("reference_rule", "RefRule"),
                           ("multi_assistant", "Multi"), ("integrity_any", "Integrity")]:
            k, n, (p, lo, hi) = d[key]
            out.append(_m(L + short, p)); out.append(_m(L + short + "Lo", lo)); out.append(_m(L + short + "Hi", hi))
            out.append(_num(L + short + "K", k))
        out.append(_num(L + "MedComp", int(d["median_components"])))
        out.append(_num(L + "MaxComp", int(d["max_components"])))
        out.append(_num(L + "MedTok", int(d["median_tokens"])))
        out.append(_num(L + "MaxTok", int(d["max_tokens"])))
        out.append(_num(L + "MedAlways", int(d["median_always_loaded"])))
        out.append(_m(L + "MedDur", d["median_duration_s"])); out.append(_m(L + "PNinetyfiveDur", d["p95_duration_s"]))
        fb = d["findings_by_scope"]; tot = sum(fb.values()) or 1
        out.append(_m(L + "PctFindingsBeyond", 100 * (tot - fb.get("FILE", 0)) / tot))
        for rid, (name, fam) in CANDIDATE_RULES.items():
            key = "".join(w.capitalize() for w in rid.replace("/", "-").split("-"))
            k, n, (p, lo, hi) = d["per_rule"][rid]
            out.append(_m(L + key, p)); out.append(_m(L + key + "Lo", lo)); out.append(_m(L + key + "Hi", hi))
    out.append(_num("nAuditedFindings", sum(a["audited"] for a in s.get("audit", {}).values())))
    out.append(_num("nAuditedRepos", s.get("audit_repos", 0)))
    out.append(_num("nGatingFindings", sum(s["audit"][r]["audited"] for r in s["reported_rules"] if r in s.get("audit", {}))))
    ranking = ", ".join(f"{name} ({n})" for name, n in s["tool_ranking"][:6])
    out.append(f"\\newcommand{{\\ToolRanking}}{{{ranking}}}\n")
    out.append(_num("nFlowRepos", s["flow_repos"]))
    cc = s["channel_check"]
    out.append(_num("ChanAgentsWithComponents", cc["agents_with_components"]))
    for key in ("topic_only", "readme_only", "curated", "agents", "agents_raw"):
        k, n, (p, lo, hi) = cc[key]
        K = "".join(w.capitalize() for w in key.split("_"))
        out.append(_m("Chan" + K, p)); out.append(_num("Chan" + K + "N", n))
    KNOWN_SUBS = ["dead", "misrouted", "runtime_output", "invocation_cycle", "documented_command_cycle",
                  "mention_cycle", "no_cycle", "generic_mcp_mention", "server_referenced",
                  "no_frontmatter", "invalid_yaml", "missing_name", "name_mismatch", "arbitrary_exec",
                  "bash_star", "bare_tool", "bypassPermissions", "dontAsk", "acceptEdits", "all_mcp",
                  "diverged", "identical", "referenced"]
    all_audit_rules = set(CANDIDATE_RULES) | {REFERENCE_RULE} | WITHDRAWN
    for rid in sorted(all_audit_rules):
        key = "".join(w.capitalize() for w in rid.replace("/", "-").split("-"))
        if rid not in s.get("audit", {}):
            out.append(_num("Aud" + key + "N", 0)); out.append(_num("Aud" + key + "K", 0))
            for m in ("", "Lo", "Hi"):
                out.append(_m("Aud" + key + m, 0.0))
        for sub in KNOWN_SUBS:
            subkey = "Aud" + key + "".join(w.capitalize() for w in sub.split("_"))
            if sub not in s.get("audit", {}).get(rid, {}).get("breakdown", {}):
                out.append(_m(subkey, 0.0))
    for rid in sorted(all_audit_rules):
        key = "".join(w.capitalize() for w in rid.replace("/", "-").split("-"))
        a = s.get("audit", {}).get(rid)
        if a is None:
            status = "was not exercised by the corpus and carries no figure"
        elif rid in s["reported_rules"]:
            status = "meets the bar and enters the gating tier"
        elif a["audited"] < 13:
            status = "has too few findings in this corpus to meet the bar and ships as advisory, reported provisionally outside every headline figure"
        else:
            status = "sits below the bar and ships as advisory, outside every headline figure"
        out.append(f"\\newcommand{{\\Status{key}}}{{{status}}}\n")
    for rid, a in s.get("audit", {}).items():
        key = "".join(w.capitalize() for w in rid.replace("/", "-").split("-"))
        p, lo, hi = wilson(a["confirmed"], a["audited"])
        out.append(_num("Aud" + key + "N", a["audited"])); out.append(_num("Aud" + key + "K", a["confirmed"]))
        out.append(_m("Aud" + key, p)); out.append(_m("Aud" + key + "Lo", lo)); out.append(_m("Aud" + key + "Hi", hi))
        for sub, v in a.get("breakdown", {}).items():
            subkey = "".join(w.capitalize() for w in re.sub(r"[^A-Za-z_]", "", sub).split("_") if w)
            if not subkey or sub not in KNOWN_SUBS:
                continue
            out.append(_m("Aud" + key + subkey, 100 * v / max(1, a["audited"])))
    (PAPER / "numbers.tex").write_text("".join(out))

    # Tables
    rep = s["reported_rules"]
    order = sorted(rep, key=lambda r: (rep[r]["tier"] != "gating", rep[r]["family"] == "D",
                                       -s["per_stratum"].get("SETUP", {}).get("per_rule", {}).get(r, (0, 0, (0,)))[2][0]))
    t2 = ["% Generated by scripts/analyze.py\n", "\\begin{tabular}{@{}lrrrr@{}}\n\\toprule\n",
          "Rule (family) & Scope & Setups & Collect. & Instr. \\\\\n\\midrule\n"]
    def pct(st, rid):
        d = s["per_stratum"].get(st)
        return f"{d['per_rule'][rid][2][0]:.1f}\\%" if d else "--"
    for rid in order:
        name, fam = rep[rid]["name"], rep[rid]["family"]
        sc = scope.get(rid, scope.get("frontmatter/format-valid", {"scope": "FILE"}))["scope"].replace("_", "\\_")
        mark = "" if rep[rid]["tier"] == "gating" else "$^{p}$"
        t2.append(f"{name} ({fam}){mark} & {sc} & {pct('SETUP', rid)} & {pct('COLLECTION', rid)} & {pct('INSTRUCTION_ONLY', rid)} \\\\\n")
    t2.append("\\midrule\n")
    def row(label, key):
        cells = []
        for st in ("SETUP", "COLLECTION", "INSTRUCTION_ONLY"):
            d = s["per_stratum"].get(st)
            cells.append(f"{d[key][2][0]:.1f}\\%" if d else "--")
        return f"{label} & & " + " & ".join(cells) + " \\\\\n"
    t2.append(row("Confirmed security-family defect (gating)", "confirmed_security"))
    t2.append(row("Requiring scope beyond a file (gating)", "confirmed_beyond_file"))
    t2.append(row("Any confirmed defect (gating, excl.\\ tolerated)", "any_confirmed"))
    t2.append(row("Any reported finding (incl.\\ provisional, tolerated)", "any_reported"))
    t2.append("\\midrule\n")
    t2.append(row("Reference does not resolve", "reference_rule").replace("& & ", "& FILE\\_FS & "))
    t2.append("\\bottomrule\n\\end{tabular}\n")
    t3 = ["% Generated by scripts/analyze.py\n", "\\begin{tabular}{@{}lrr@{}}\n\\toprule\n",
          "Rule (family) & Audited & Precision (95\\% CI) \\\\\n\\midrule\n"]
    for rid in order:
        a = s["audit"][rid]
        p, lo, hi = wilson(a["confirmed"], a["audited"])
        mark = "" if rep[rid]["tier"] == "gating" else "$^{p}$"
        t3.append(f"{rep[rid]['name']} ({rep[rid]['family']}){mark} & {a['audited']} & {p:.1f}\\% ({lo:.1f}--{hi:.1f}) \\\\\n")
    t3.append("\\bottomrule\n\\end{tabular}\n")
    (PAPER / "table_rules.tex").write_text("".join(t2))
    dset = s["per_stratum"].get("SETUP", {})
    te = ["% Generated by scripts/analyze.py\n", "\\begin{tabular}{@{}p{2.15cm}rp{4.05cm}@{}}\n\\toprule\n",
          "Defect & Setups & What it looks like \\\\\n\\midrule\n"]
    for rid in order:
        k, n, (p, lo, hi) = dset["per_rule"][rid]
        mark = "" if rep[rid]["tier"] == "gating" else "$^{p}$"
        te.append(f"{rep[rid]['name']}{mark} & {p:.1f}\\% ({k}) & {EXAMPLES.get(rid, '')} \\\\\n")
    te.append("\\bottomrule\n\\end{tabular}\n")
    (PAPER / "table_examples.tex").write_text("".join(te))
    (PAPER / "table_precision.tex").write_text("".join(t3))
    # Table 1: rule set by scope
    sc = s["rule_scope_counts"]
    t1 = ["% Generated by scripts/analyze.py\n"]
    for k in ("FILE", "FILE_FS", "PAIRWISE", "SETUP"):
        t1.append(f"\\newcommand{{\\scope{k.replace('_', '')}Count}}{{{sc.get(k, 0)}}}\n")
    (PAPER / "table_scope_counts.tex").write_text("".join(t1))
    t2b = ["\\begin{tabular}{@{}lrr@{}}\n\\toprule\nRule & Audited & Verdict \\\\\n\\midrule\n"]
    for rid, a in s["audit"].items():
        if rid not in rep and rid != REFERENCE_RULE:
            p, lo, hi = wilson(a["confirmed"], a["audited"])
            t2b.append(f"{rid.replace('_', '-')} & {a['audited']} & {p:.0f}\\% (withdrawn) \\\\\n")
    t2b.append("\\bottomrule\n\\end{tabular}\n")
    (PAPER / "table_withdrawn.tex").write_text("".join(t2b))
    # Table 5: catalog by category with scope mix and reported count
    cats = defaultdict(lambda: {"n": 0, "scopes": Counter(), "reported": 0})
    code = {"FILE": "F", "FILE_FS": "F+", "PAIRWISE": "P", "SETUP": "S"}
    for rid, v in scope.items():
        cat = rid.split("/")[0]
        cats[cat]["n"] += 1
        cats[cat]["scopes"][code[v["scope"]]] += 1
        if rid in rep:
            cats[cat]["reported"] += 1
    t5 = ["% Generated by scripts/analyze.py\n", "\\begin{tabular}{@{}lrlr@{}}\n\\toprule\n",
          "Category & Rules & Scope mix & Reported \\\\\n\\midrule\n"]
    for cat in sorted(cats, key=lambda c: -cats[c]["n"]):
        d = cats[cat]
        mix = ", ".join(f"{n}{k}" for k, n in sorted(d["scopes"].items(), key=lambda kv: -kv[1]))
        t5.append(f"{cat.replace('_', '-')} & {d['n']} & {mix} & {d['reported'] or '--'} \\\\\n")
    tot = Counter(code[v["scope"]] for v in scope.values())
    mix = ", ".join(f"{n}{k}" for k, n in sorted(tot.items(), key=lambda kv: -kv[1]))
    t5.append("\\midrule\n")
    t5.append(f"Total & {len(scope)} & {mix} & {len(rep)} \\\\\n\\bottomrule\n\\end{{tabular}}\n")
    (PAPER / "table_catalog.tex").write_text("".join(t5))


def _write_fig(s: dict) -> None:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(11, 4.2), gridspec_kw={"width_ratios": [1, 1.5]})
    names = {"SETUP": "Setups", "COLLECTION": "Collections", "INSTRUCTION_ONLY": "Instruction-only"}
    cols = {"SETUP": "#c0392b", "COLLECTION": "#34495e", "INSTRUCTION_ONLY": "#7f8c8d"}
    xs, ys, err, labels = [], [], [], []
    for i, st in enumerate(("SETUP", "COLLECTION", "INSTRUCTION_ONLY")):
        d = s["per_stratum"].get(st)
        if not d:
            continue
        k, n, (p, lo, hi) = d["any_confirmed"]
        xs.append(i); ys.append(p); err.append([p - lo, hi - p]); labels.append(f"{names[st]}\n(n={n})")
        ax1.bar(i, p, color=cols[st], width=0.6)
        ax1.text(i, hi + 1, f"{p:.1f}%", ha="center", fontweight="bold")
    ax1.errorbar(xs, ys, yerr=list(zip(*err)) if err else None, fmt="none", ecolor="black", capsize=4)
    ax1.set_xticks(xs); ax1.set_xticklabels(labels); ax1.set_ylabel("Confirmed-defect prevalence (%)")
    ax1.set_title("Headline confirmed-defect rate"); ax1.set_ylim(0, max(ys + [10]) * 1.35)
    d = s["per_stratum"].get("SETUP", {})
    rows = [(s["reported_rules"][rid]["name"], d["per_rule"][rid][2]) for rid in s["headline_rules"]]
    rows.sort(key=lambda r: r[1][0])
    for i, (name, (p, lo, hi)) in enumerate(rows):
        ax2.barh(i, p, color="#3b5f8a"); ax2.errorbar(p, i, xerr=[[p - lo], [hi - p]], fmt="none", ecolor="black", capsize=3)
        ax2.text(hi + 0.3, i, f"{p:.1f}", va="center", fontsize=9)
    ax2.set_yticks(range(len(rows))); ax2.set_yticklabels([r[0] for r in rows]); ax2.set_xlabel("Setup prevalence (%)")
    ax2.set_title("Gating-tier prevalence among setups (95% CI)")
    for ax in (ax1, ax2):
        ax.spines["top"].set_visible(False); ax.spines["right"].set_visible(False)
    fig.tight_layout(); fig.savefig(FIG / "results.png", dpi=200); fig.savefig(FIG / "results.pdf")


if __name__ == "__main__":
    main()
