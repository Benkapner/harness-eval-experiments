#!/usr/bin/env python3
"""Reanalysis of the published corpus with harness-eval 8.0.2.

Three scans of the same 3,171 repositories are compared:
  old     data/results.jsonl.gz          harness-eval 7.15.0 at the pinned commits (published)
  pinned  data/results_v802_pinned.jsonl harness-eval 8.0.2 at the same pinned commits (instrument change)
  head    data/results_v802_head.jsonl   harness-eval 8.0.2 at the default-branch HEAD (ecosystem change)

The unit of analysis and the strata are fixed once, from the published scan,
so every table below counts the same 2,660 setups and 511 collections. A
repository that could not be re-fetched is reported as attrition, not dropped
from the denominator.

Category definitions are mechanical. Each starts from a rule's findings and
applies a documented exclusion that a reader can re-derive from the finding's
own evidence (the grant text, the package spec, the file path). No model
verdict enters a headline number; the historical model adjudication is
reported in its own table for comparison.

Outputs (all under data/v802/ and figures/):
  summary.json         every number, machine readable
  tex/numbers.tex      \\newcommand macros for the paper
  tex/tab_*.tex        the tables
  ../figures/results_v802.{png,pdf}
"""
from __future__ import annotations

import csv
import gzip
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data"
OUT = DATA / "v802"
TEX = OUT / "tex"
FIG = ROOT / "figures"
sys.path.insert(0, str(ROOT / "scripts"))
from analyze import corpus, stratum, read_results  # noqa: E402  (published corpus definition)

OLD = DATA / "results.jsonl"
PINNED = DATA / "results_v802_pinned.jsonl"
HEAD = DATA / "results_v802_head.jsonl"
AUDIT_NEW = DATA / "audit_findings_v802.jsonl"
AUDIT_OLD = DATA / "audit_findings.jsonl"
HUMAN = DATA / "defects_table_reviewed.csv"
ADJ = DATA / "adjudications.jsonl"
RULES = DATA / "rules_v802.json"

# ---------------------------------------------------------------------------
# Grant vocabulary. Mirrors the scanner's and the audit's lists on purpose; the
# three agree by construction, so a disagreement with the client documentation
# must be caught by the documentation check, not by cross-implementation
# agreement (Section "shared error").
SHELLS_AND_INTERPRETERS = {"sh", "bash", "zsh", "dash", "fish", "eval", "exec", "sudo", "doas",
                           "python", "python3", "perl", "ruby", "node", "bun", "deno", "php", "lua",
                           "awk", "gawk", "mawk", "nawk", "sed", "npx", "bunx", "uvx", "pipx",
                           "vim", "vi", "nvim", "less", "man"}
# Wrappers Claude Code strips before matching (timeout, nohup, bare xargs,
# env assignments): the effect of a prefix rule on them is undocumented.
STRIPPED_WRAPPERS = {"timeout", "nohup", "xargs", "env", "time", "nice", "stdbuf"}
# Documented as not auto-approved by a prefix rule (the 7.15 shared error).
PREFIX_RULE_EXCLUDED = {"find", "watch", "setsid", "ionice", "flock"}
NETWORK_TOOLS = {"curl", "wget"}
INDIRECT_EXEC = {"docker", "podman", "make", "ssh"}
GRANT_RE = re.compile(r"^Bash\(\s*(?:[\w./-]*/)?([\w.+-]+)")

FIXTURE_RE = re.compile(r"/(?:tests?|testdata|fixtures?|__fixtures__|__snapshots__|benchmarks?|evaluation|corpus|vulnerable-configs)/")
TEMPLATE_RE = re.compile(r"/(?:templates?|examples?|_templates|registry|sample|profiles|tutorials?|lessons?|config/source|\d\d-[a-z]+/projects)/")
ARCHIVE_RE = re.compile(r"/(?:archive|_archive|deprecated|old)/")

CATEGORIES = [
    # id, rule, family, display name
    ("S1", "mcp/unpinned-package", "S", "Unpinned MCP package declaration"),
    ("S2", "cross/overpermissive-grants", "S", "Broad execution grant (settings)"),
    ("S3", "content/allowed-tools-auto-approve", "S", "Broad skill tool preapproval"),
    ("Q1", "agent/description-required", "Q", "Agent description missing"),
    ("P1", "frontmatter/format-valid", "P", "Skill without frontmatter"),
    ("P2", "frontmatter/description-required", "P", "Skill description missing"),
]
# Reported beside the six, never in the comparable union: an 8.0 sub-check the
# 7.15 instrument did not have.
EXTRA = [
    ("P3", "frontmatter/format-valid", "P", "Skill frontmatter field type or format deviation (8.0 sub-checks)"),
]
# The 31 candidate rules of the published study, for the raw-union row (the two
# advisory split-offs, hooks/pre-trust-permissions and command/script-exists,
# were never candidates for a figure).
CANDIDATES_31 = [
    "mcp/unpinned-package", "cross/overpermissive-grants", "security/dangerous-permission-grant",
    "hooks/permission-prompt-disabled", "hooks/local-settings-committed",
    "hooks/api-key-helper", "hooks/base-url-override", "hooks/env-credential-override",
    "hooks/dangerous-command", "content/allowed-tools-auto-approve", "mcp/auto-approve-risk",
    "mcp/no-plaintext-secrets", "mcp/endpoint-integrity", "security/credential-file-present",
    "structural/symlink-escape", "frontmatter/format-valid", "frontmatter/description-required",
    "agent/description-required", "structural/skill-md-exists", "hooks/command-script-exists",
    "hooks/valid-structure", "hooks/matcher-matches-no-tool", "hooks/permission-contradiction",
    "mcp/valid-config", "mcp/json-duplicate-keys", "hooks/json-duplicate-keys", "claude-md/include-exists",
    "command/references-nonexistent-skill", "agent/referenced-skills-exist",
    "cross/multi-assistant-drift", "mcp/cross-assistant-divergence",
]


def load(path: Path) -> dict[str, dict]:
    recs = read_results(path) if path.suffix != ".gz" else [json.loads(l) for l in gzip.open(path, "rt") if l.strip()]
    by = {}
    for r in recs:
        by[r["full_name"]] = r   # a later record (resumed scan) replaces an earlier one
    return by


def pct(k: int, n: int) -> float:
    return round(100.0 * k / n, 1) if n else 0.0


# ---------------------------------------------------------------------------
# Finding classifiers. Each returns a (counts, reason) decision from the
# finding's own text, so a reader can re-derive it from the released records.

def grant_cmd(entry: str) -> str:
    m = GRANT_RE.match(entry or "")
    return m.group(1).lower() if m else ""


def classify_settings_grant(f: dict) -> str:
    """S2 classes: unrestricted | arbitrary-exec | stripped-wrapper | prefix-excluded |
    network | indirect | bare-write-tool | other."""
    entry = (f.get("data") or {}).get("entry")
    if not entry:
        m = re.search(r"entry '([^']+)'", f.get("message", ""))
        entry = m.group(1) if m else ""
    if entry in ("Bash(*)", "Bash(:*)", "Bash"):
        return "unrestricted"
    if entry in ("Edit", "Write", "WebFetch"):
        return "bare-write-tool"
    c = grant_cmd(entry)
    if c in PREFIX_RULE_EXCLUDED:
        return "prefix-excluded"
    if c in STRIPPED_WRAPPERS:
        return "stripped-wrapper"
    if c in SHELLS_AND_INTERPRETERS:
        return "arbitrary-exec"
    if c in NETWORK_TOOLS:
        return "network"
    if c in INDIRECT_EXEC:
        return "indirect"
    return "other"


def skill_grant_tools(f: dict) -> list[str]:
    d = f.get("data") or {}
    if isinstance(d.get("tools"), str):
        return [t.strip() for t in d["tools"].split(",") if t.strip()]
    m = re.search(r"without user confirmation: (.*?)(?:\. This is not a sandbox.*)?$", f.get("message", ""), re.S)
    if m:
        return [t.strip() for t in m.group(1).rstrip(".").split(",") if t.strip()]
    m = re.search(r"allowed-tools includes '([^']+)'", f.get("message", ""))     # 7.15 wording
    return [m.group(1)] if m else []


def classify_skill_grant(f: dict) -> str:
    """S3 classes for one finding: unrestricted | arbitrary-exec | stripped-wrapper |
    prefix-excluded | scoped (medium class) | none."""
    msg = f.get("message", "")
    tools = skill_grant_tools(f)
    if "unrestricted shell" in msg or "auto-approves shell execution" in msg:
        classes = set()
        for t in tools:
            tl = t.lower()
            if tl in ("bash", "bash(*)", "bash(:*)"):
                classes.add("unrestricted")
                continue
            c = grant_cmd(t)
            if c in PREFIX_RULE_EXCLUDED:
                classes.add("prefix-excluded")
            elif c in STRIPPED_WRAPPERS:
                classes.add("stripped-wrapper")
            elif c in SHELLS_AND_INTERPRETERS:
                classes.add("arbitrary-exec")
        for k in ("unrestricted", "arbitrary-exec", "stripped-wrapper", "prefix-excluded"):
            if k in classes:
                return k
        return "none"
    return "scoped"


def mcp_exclusion(f: dict) -> str:
    """S1: a declaration in a fixture or template path is a distributed
    example, reported apart from live configuration (the published policy,
    now applied mechanically)."""
    rel = "/" + (f.get("file") or "").lower() + "/"
    if FIXTURE_RE.search(rel):
        return "fixture"
    if TEMPLATE_RE.search(rel):
        return "template"
    return "live"


def frontmatter_class(f: dict) -> str:
    msg = f.get("message", "")
    if msg.startswith("No YAML frontmatter"):
        rel = "/" + (f.get("file") or "").lower() + "/"
        return "archived" if ARCHIVE_RE.search(rel) else "no-frontmatter"
    if "is missing from frontmatter" in msg:
        return "missing-field"
    if "does not match directory" in msg:
        return "name-mismatch"
    if "must be 1-64 lowercase" in msg:
        return "name-format"
    if "must be" in msg:
        return "field-type"
    return "other"


def agent_class(f: dict) -> str:
    """Q1: a root-level agents/ directory also holds documentation; a file
    without frontmatter there is not a subagent definition (published policy)."""
    fl = (f.get("file") or "").replace("\\", "/")
    name = fl.rsplit("/", 1)[-1].lower()
    if name in ("readme.md", "index.md", "changelog.md", "contributing.md") or name.isupper():
        return "doc-like"
    if "/.claude/agents/" not in fl and "/.github/agents/" not in fl and "/agents/" in fl:
        return "root-agents-dir"
    return "agent"


def category_hits(rec: dict | None, cat: str) -> dict:
    """Per repository: the finding classes seen for a category, with counts."""
    out: Counter = Counter()
    if not rec or rec.get("status") != "ok":
        return out
    for f in rec.get("findings", []):
        rule = f.get("rule")
        if cat == "S1" and rule == "mcp/unpinned-package":
            out[mcp_exclusion(f)] += 1
        elif cat == "S2" and rule == "cross/overpermissive-grants":
            out[classify_settings_grant(f)] += 1
        elif cat == "S3" and rule == "content/allowed-tools-auto-approve":
            out[classify_skill_grant(f)] += 1
        elif cat == "Q1" and rule == "agent/description-required":
            out[agent_class(f)] += 1
        elif cat in ("P1", "P3") and rule == "frontmatter/format-valid":
            out[frontmatter_class(f)] += 1
        elif cat == "P2" and rule == "frontmatter/description-required":
            out["missing"] += 1
    return out


# Which classes count toward the category (the documented inclusion policy).
INCLUDE = {
    "S1": {"live"},
    "S2": {"unrestricted", "arbitrary-exec"},
    "S3": {"unrestricted", "arbitrary-exec"},
    "Q1": {"agent"},
    "P1": {"no-frontmatter"},
    "P2": {"missing"},
    "P3": {"missing-field", "name-mismatch", "name-format", "field-type"},
}
# Raw = the rule fired at all (before any exclusion).


def has(rec: dict | None, cat: str, raw: bool = False) -> bool:
    hits = category_hits(rec, cat)
    if raw:
        return sum(hits.values()) > 0
    return any(hits[c] for c in INCLUDE[cat])


def fired(rec: dict | None, rule: str) -> bool:
    return bool(rec) and rec.get("status") == "ok" and any(f.get("rule") == rule for f in rec.get("findings", []))


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    TEX.mkdir(exist_ok=True)
    old_recs = read_results(OLD)
    corp = corpus(old_recs)                       # the published unit of analysis
    for r in corp:
        r["stratum"] = stratum(r)
    names = [r["full_name"] for r in corp]
    strata = {r["full_name"]: r["stratum"] for r in corp}
    old = {r["full_name"]: r for r in corp}
    pinned = load(PINNED) if PINNED.exists() else {}
    head = load(HEAD) if HEAD.exists() else {}
    rules = {r["id"]: r for r in json.loads(RULES.read_text())} if RULES.exists() else {}

    S = {"corpus": {"setups": sum(1 for n in names if strata[n] == "SETUP"),
                    "collections": sum(1 for n in names if strata[n] == "COLLECTION")}}
    n_set, n_col = S["corpus"]["setups"], S["corpus"]["collections"]
    setups = [n for n in names if strata[n] == "SETUP"]
    cols = [n for n in names if strata[n] == "COLLECTION"]

    # ---- scan coverage --------------------------------------------------
    def coverage(scan: dict) -> dict:
        st = Counter((scan.get(n) or {}).get("status", "not_scanned") for n in names)
        ver = Counter((scan.get(n) or {}).get("tool_version") for n in names if (scan.get(n) or {}).get("status") == "ok")
        return {"status": dict(st), "tool_version": dict(ver), "scanned": sum(st.values()) - st["not_scanned"]}
    S["coverage"] = {"pinned": coverage(pinned), "head": coverage(head)}
    ok_p = [n for n in names if (pinned.get(n) or {}).get("status") == "ok"]
    ok_h = [n for n in names if (head.get(n) or {}).get("status") == "ok"]
    S["coverage"]["pinned"]["ok"] = len(ok_p)
    S["coverage"]["head"]["ok"] = len(ok_h)
    # commit drift between the pin and HEAD at scan time
    moved = sum(1 for n in ok_p if pinned[n].get("head_now") and pinned[n]["head_now"] != pinned[n]["commit"])
    S["drift"] = {"moved_head": moved, "of": len(ok_p),
                  "unfetchable_pinned": S["coverage"]["pinned"]["status"].get("clone_failed", 0),
                  "unfetchable_head": S["coverage"]["head"]["status"].get("clone_failed", 0)}

    # ---- component denominators (from the published inventory, fixed) ----
    def with_type(n: str, t: str) -> bool:
        return (old[n]["inventory"].get("component_types") or {}).get(t, 0) > 0
    S["denominators"] = {"setups_with_mcp": sum(1 for n in setups if with_type(n, "mcp_config")),
                         "setups_with_hooks": sum(1 for n in setups if with_type(n, "hooks")),
                         "setups_with_skills": sum(1 for n in setups if with_type(n, "skill")),
                         "setups_with_agents": sum(1 for n in setups if with_type(n, "agent")),
                         "collections_with_skills": sum(1 for n in cols if with_type(n, "skill"))}

    # ---- Table 1: categories on the 8.0.2 pinned scan -------------------
    def table1(scan: dict, scan_names: list[str]) -> dict:
        rows = {}
        for cid, rule, fam, name in CATEGORIES + EXTRA:
            ks = sum(1 for n in scan_names if strata[n] == "SETUP" and has(scan.get(n), cid))
            kc = sum(1 for n in scan_names if strata[n] == "COLLECTION" and has(scan.get(n), cid))
            rs = sum(1 for n in scan_names if strata[n] == "SETUP" and has(scan.get(n), cid, raw=True))
            rows[cid] = {"rule": rule, "family": fam, "name": name, "setups": ks, "collections": kc,
                         "setups_pct": pct(ks, n_set), "collections_pct": pct(kc, n_col), "setups_raw": rs}
        def union(fams, cats=None):
            cats = cats or [c for c in CATEGORIES if c[2] in fams]
            us = sum(1 for n in scan_names if strata[n] == "SETUP" and any(has(scan.get(n), c[0]) for c in cats))
            uc = sum(1 for n in scan_names if strata[n] == "COLLECTION" and any(has(scan.get(n), c[0]) for c in cats))
            return {"setups": us, "collections": uc, "setups_pct": pct(us, n_set), "collections_pct": pct(uc, n_col)}
        rows["any_S"] = union("S"); rows["any_Q"] = union("Q"); rows["any_P"] = union("P")
        rows["any_six"] = union("SQP")
        rows["any_six_plus_P3"] = union("", CATEGORIES + EXTRA)
        return rows
    S["table1_pinned"] = table1(pinned, names)
    S["table1_old"] = table1(old, names)
    S["table1_head"] = table1(head, names)
    # conditional proportions
    t = S["table1_pinned"]
    d = S["denominators"]
    S["conditional_pinned"] = {
        "S1_of_mcp": pct(t["S1"]["setups"], d["setups_with_mcp"]),
        "S2_of_hooks": pct(t["S2"]["setups"], d["setups_with_hooks"]),
        "S3_of_skills": pct(t["S3"]["setups"], d["setups_with_skills"]),
        "Q1_of_agents": pct(t["Q1"]["setups"], d["setups_with_agents"]),
    }

    # ---- Table 2: accounting ladder, 7.15 and 8.0.2 ---------------------
    # Five stages, each a documented restriction of the one before:
    #   raw31      any of the 31 candidate rules fired
    #   raw6       any of the six rules fired, any finding class
    #   class      six rules, security/specification class only (the grant and
    #              frontmatter sub-check split the published pipeline applied)
    #   nofind     the documented find/watch exception removed
    #   final      path-based exclusions (fixture and template paths, archived
    #              skills, documentation files in agents/) and the undetermined
    #              stripped-wrapper grants removed
    CLASS_STAGE = {"S1": {"live", "fixture", "template"}, "S2": {"unrestricted", "arbitrary-exec", "stripped-wrapper", "prefix-excluded"},
                   "S3": {"unrestricted", "arbitrary-exec", "stripped-wrapper", "prefix-excluded"}, "Q1": {"agent", "root-agents-dir", "doc-like"},
                   "P1": {"no-frontmatter", "archived"}, "P2": {"missing"}}
    NOFIND_STAGE = {k: v - {"prefix-excluded"} for k, v in CLASS_STAGE.items()}

    def any_cat(rec, stage: dict) -> bool:
        return any(any(category_hits(rec, c[0])[k] for k in stage[c[0]]) for c in CATEGORIES)

    def ladder(scan: dict) -> dict:
        raw31 = sum(1 for n in setups if any(fired(scan.get(n), r) for r in CANDIDATES_31))
        raw6 = sum(1 for n in setups if any(has(scan.get(n), c[0], raw=True) for c in CATEGORIES))
        klass = sum(1 for n in setups if any_cat(scan.get(n), CLASS_STAGE))
        nofind = sum(1 for n in setups if any_cat(scan.get(n), NOFIND_STAGE))
        final = sum(1 for n in setups if any(has(scan.get(n), c[0]) for c in CATEGORIES))
        out = {"raw31": raw31, "raw6": raw6, "class": klass, "nofind": nofind, "final": final}
        out.update({f"{k}_pct": pct(v, n_set) for k, v in list(out.items())})
        return out
    S["ladder_old"] = ladder(old)
    S["ladder_pinned"] = ladder(pinned)
    S["ladder_published"] = {"raw31": 678, "raw6": 503, "nofind": 488, "final": 475,
                             "note": "the published pipeline's stages: its raw rows already applied the class split, and its final row applied model-assisted inclusion decisions"}

    # ---- Table 3: instrument change (same bytes, 7.15 -> 8.0.2) ---------
    both = [n for n in names if (pinned.get(n) or {}).get("status") == "ok"]
    inst = {}
    for cid, rule, fam, name in CATEGORIES:
        o = {n for n in both if has(old.get(n), cid)}
        p = {n for n in both if has(pinned.get(n), cid)}
        o_raw = {n for n in both if has(old.get(n), cid, raw=True)}
        p_raw = {n for n in both if has(pinned.get(n), cid, raw=True)}
        inst[cid] = {"name": name, "n": len(both), "old": len(o), "new": len(p), "lost": len(o - p), "gained": len(p - o),
                     "old_raw": len(o_raw), "new_raw": len(p_raw), "lost_raw": len(o_raw - p_raw), "gained_raw": len(p_raw - o_raw)}
    # reasons for S3 gain: string-form allowed-tools (7.15 parsed lists only)
    S["instrument"] = inst
    # grant class breakdown, 7.15 vs 8.0.2, over repositories
    def class_counts(scan: dict, cid: str) -> dict:
        c: Counter = Counter()
        for n in both:
            for k, v in category_hits(scan.get(n), cid).items():
                if v:
                    c[k] += 1
        return dict(c)
    S["classes"] = {cid: {"old": class_counts(old, cid), "new": class_counts(pinned, cid)} for cid in ("S1", "S2", "S3", "Q1", "P1", "P3")}

    # ---- Table 4: persistence (pinned -> HEAD, same scanner) ------------
    pers = {}
    for cid, rule, fam, name in CATEGORIES:
        flagged = [n for n in names if (pinned.get(n) or {}).get("status") == "ok" and has(pinned.get(n), cid)]
        still = sum(1 for n in flagged if (head.get(n) or {}).get("status") == "ok" and has(head.get(n), cid))
        fixed = sum(1 for n in flagged if (head.get(n) or {}).get("status") == "ok" and not has(head.get(n), cid))
        gone = sum(1 for n in flagged if (head.get(n) or {}).get("status") not in ("ok", None))
        unscanned = sum(1 for n in flagged if head.get(n) is None)
        new = sum(1 for n in names if (head.get(n) or {}).get("status") == "ok" and has(head.get(n), cid)
                  and (pinned.get(n) or {}).get("status") == "ok" and not has(pinned.get(n), cid))
        unchanged_repo = sum(1 for n in flagged if (pinned.get(n) or {}).get("head_now") == pinned[n]["commit"])
        pers[cid] = {"name": name, "flagged_at_pin": len(flagged), "still_at_head": still, "resolved_at_head": fixed,
                     "repo_gone": gone, "not_scanned": unscanned, "new_at_head": new, "repo_unchanged": unchanged_repo,
                     "resolved_pct_of_rescanned": pct(fixed, still + fixed)}
    S["persistence"] = pers

    # ---- Table 5: MCP declaration denominator ---------------------------
    decl = Counter()
    for n in ok_p:
        md = pinned[n].get("mcp_declarations") or {}
        for k, v in md.items():
            if isinstance(v, int):
                decl[k] += v
    decl_setups = Counter()
    for n in ok_p:
        if strata[n] != "SETUP":
            continue
        md = pinned[n].get("mcp_declarations") or {}
        for k, v in md.items():
            if isinstance(v, int):
                decl_setups[k] += v
    S["mcp_declarations"] = {"all": dict(decl), "setups": dict(decl_setups)}
    pk = decl_setups.get("package", 0)
    S["mcp_declarations"]["setups_pct_package_unpinned_or_tag"] = pct(decl_setups.get("package_unpinned", 0) + decl_setups.get("package_tag", 0), pk)
    S["mcp_declarations"]["setups_pct_package_of_total"] = pct(pk, decl_setups.get("total", 0))
    S["mcp_declarations"]["setups_with_any_declaration"] = sum(1 for n in ok_p if strata[n] == "SETUP" and (pinned[n].get("mcp_declarations") or {}).get("total", 0) > 0)

    # ---- mechanical audit agreement on the 8.0.2 scan --------------------
    if AUDIT_NEW.exists():
        rows = [json.loads(l) for l in AUDIT_NEW.read_text().splitlines() if l.strip()]
        agg: dict = {}
        for cid, rule, fam, name in CATEGORIES:
            rs = [r for r in rows if r["rule"] == rule]
            det = [r for r in rs if r["verdict"] != "unverifiable"]
            conf = [r for r in det if r["verdict"] == "confirmed"]
            agg[cid] = {"rule": rule, "findings": len(rs), "determinate": len(det), "confirmed": len(conf),
                        "refuted": len(det) - len(conf), "unverifiable": len(rs) - len(det),
                        "agreement_pct": pct(len(conf), len(det)), "subclasses": dict(Counter(r["sub"] for r in rs))}
        S["audit_new"] = agg
        S["audit_new_repos"] = len({r["repo"] for r in rows})
        S["audit_new_findings"] = len(rows)

    # ---- human verdicts (published review) joined to the 8.0.2 pairs -------
    if HUMAN.exists():
        hv = {}
        for r in csv.DictReader(HUMAN.open()):
            hv[(r["repo"], r["rule"])] = r["human_reviewer_verdict"].strip().lower().startswith("yes")
        join = {}
        for cid, rule, fam, name in CATEGORIES:
            pairs = [(n, rule) for n in both if has(pinned.get(n), cid, raw=True)]
            incl = {(n, rule) for n in both if has(pinned.get(n), cid)}
            with_h = [p for p in pairs if p in hv]
            agree = sum(1 for p in with_h if hv[p] == (p in incl))
            h_yes_excl = sum(1 for p in with_h if hv[p] and p not in incl)
            h_no_incl = sum(1 for p in with_h if not hv[p] and p in incl)
            join[cid] = {"pairs_8_0_2": len(pairs), "with_human_verdict": len(with_h), "agree": agree,
                         "agree_pct": pct(agree, len(with_h)), "human_yes_but_excluded": h_yes_excl,
                         "human_no_but_included": h_no_incl, "new_pairs_without_verdict": len(pairs) - len(with_h)}
        S["human_join"] = join
        S["human_total_verdicts"] = len(hv)

    # ---- historical model adjudication, for the comparison table ---------
    if ADJ.exists():
        adj = [json.loads(l) for l in ADJ.read_text().splitlines() if l.strip()]
        S["adjudication_hist"] = {"pairs": len(adj), "verdicts": dict(Counter(a.get("verdict") for a in adj)),
                                  "model": sorted({a.get("model") for a in adj if a.get("model")})}

    # ---- stratum stability under 8.0.2 discovery ------------------------
    changed = 0
    for n in ok_p:
        if stratum(pinned[n]) != strata[n]:
            changed += 1
    S["stratum_changed_under_802"] = {"changed": changed, "of": len(ok_p)}

    # ---- effect/tier of the six under 8.0.2 ----------------------------
    S["rule_meta"] = {c[1]: {k: rules.get(c[1], {}).get(k) for k in ("effect", "tier", "severity", "scope")} for c in CATEGORIES}

    (OUT / "summary.json").write_text(json.dumps(S, indent=1, sort_keys=True))
    write_tex(S)
    try:
        figure(S)
    except Exception as e:  # noqa: BLE001
        print(f"figure skipped: {e}", file=sys.stderr)
    print(json.dumps({k: S[k] for k in ("corpus", "coverage", "drift", "ladder_old", "ladder_pinned")}, indent=1))
    for cid in ("S1", "S2", "S3", "Q1", "P1", "P2", "P3"):
        t = S["table1_pinned"][cid]
        print(f"{cid} {t['name'][:40]:40s} setups {t['setups']:4d} ({t['setups_pct']}%)  collections {t['collections']:3d} ({t['collections_pct']}%)")
    print("union six:", S["table1_pinned"]["any_six"], "| any S:", S["table1_pinned"]["any_S"])
    for cid, v in S["instrument"].items():
        print(f"instrument {cid}: 7.15 {v['old']} -> 8.0.2 {v['new']} (lost {v['lost']}, gained {v['gained']})")
    for cid, v in S["persistence"].items():
        print(f"persist {cid}: flagged {v['flagged_at_pin']} still {v['still_at_head']} resolved {v['resolved_at_head']} gone {v['repo_gone']} new {v['new_at_head']}")
    print("mcp declarations (setups):", S["mcp_declarations"]["setups"])


# ---------------------------------------------------------------------------
CID = {"S1": "SOne", "S2": "STwo", "S3": "SThree", "Q1": "QOne", "P1": "POne", "P2": "PTwo", "P3": "PThree"}


def _camel(k: str) -> str:
    k = k.replace("8_0_2", "new").replace("31", "ThirtyOne").replace("6", "Six")
    return "".join(p[:1].upper() + p[1:] for p in k.split("_") if p)


def _m(name: str, val) -> str:
    for cid, word in CID.items():
        name = name.replace(cid, word)
    assert not any(ch.isdigit() for ch in name), name
    return f"\\newcommand{{\\{name}}}{{{val}}}\n"


def write_tex(S: dict) -> None:
    n = []
    c = S["corpus"]
    n.append(_m("NSetups", f"{c['setups']:,}")); n.append(_m("NCollections", f"{c['collections']:,}")); n.append(_m("NCorpus", f"{c['setups'] + c['collections']:,}"))
    cov = S["coverage"]
    n.append(_m("NPinnedOk", f"{cov['pinned']['ok']:,}")); n.append(_m("NHeadOk", f"{cov['head']['ok']:,}"))
    n.append(_m("NPinnedUnfetchable", S["drift"]["unfetchable_pinned"])); n.append(_m("NHeadUnfetchable", S["drift"]["unfetchable_head"]))
    n.append(_m("NMovedHead", f"{S['drift']['moved_head']:,}")); n.append(_m("PctMovedHead", pct(S["drift"]["moved_head"], S["drift"]["of"])))
    for cid in ("S1", "S2", "S3", "Q1", "P1", "P2", "P3"):
        t = S["table1_pinned"][cid]
        n.append(_m(f"{cid}Setups", t["setups"])); n.append(_m(f"{cid}SetupsPct", t["setups_pct"]))
        n.append(_m(f"{cid}Cols", t["collections"])); n.append(_m(f"{cid}ColsPct", t["collections_pct"]))
        to = S["table1_old"][cid]
        n.append(_m(f"{cid}OldSetups", to["setups"])); n.append(_m(f"{cid}OldSetupsPct", to["setups_pct"]))
    for key, mac in (("any_S", "AnyS"), ("any_Q", "AnyQ"), ("any_P", "AnyP"), ("any_six", "AnySix"), ("any_six_plus_P3", "AnySixPlus")):
        t = S["table1_pinned"][key]
        n.append(_m(f"{mac}Setups", t["setups"])); n.append(_m(f"{mac}SetupsPct", t["setups_pct"]))
        n.append(_m(f"{mac}Cols", t["collections"])); n.append(_m(f"{mac}ColsPct", t["collections_pct"]))
        to = S["table1_old"][key]
        n.append(_m(f"{mac}OldSetups", to["setups"])); n.append(_m(f"{mac}OldSetupsPct", to["setups_pct"]))
    for k, v in S["conditional_pinned"].items():
        n.append(_m("Cond" + k.replace("_", ""), v))
    for k, v in S["denominators"].items():
        n.append(_m("Den" + _camel(k), f"{v:,}"))
    for tag, lad in (("Old", S["ladder_old"]), ("New", S["ladder_pinned"])):
        for k, v in lad.items():
            n.append(_m(f"Ladder{tag}" + _camel(k), v))
    for cid, v in S["instrument"].items():
        for k in ("old", "new", "lost", "gained"):
            n.append(_m(f"Inst{cid}{k.capitalize()}", v[k]))
    for cid, v in S["persistence"].items():
        for k in ("flagged_at_pin", "still_at_head", "resolved_at_head", "repo_gone", "new_at_head", "resolved_pct_of_rescanned"):
            n.append(_m(f"Pers{cid}" + _camel(k), v[k]))
    md = S["mcp_declarations"]
    for k, v in md["setups"].items():
        n.append(_m("Decl" + _camel(k), f"{v:,}"))
    n.append(_m("DeclPctUnpinnedOrTag", md["setups_pct_package_unpinned_or_tag"]))
    n.append(_m("DeclPctPackage", md["setups_pct_package_of_total"]))
    n.append(_m("DeclSetupsWithAny", md["setups_with_any_declaration"]))
    if "audit_new" in S:
        for cid, v in S["audit_new"].items():
            n.append(_m(f"Audit{cid}Findings", v["findings"])); n.append(_m(f"Audit{cid}Agree", v["agreement_pct"])); n.append(_m(f"Audit{cid}Refuted", v["refuted"]))
        n.append(_m("AuditRepos", f"{S['audit_new_repos']:,}")); n.append(_m("AuditFindings", f"{S['audit_new_findings']:,}"))
    if "human_join" in S:
        for cid, v in S["human_join"].items():
            for k in ("pairs_8_0_2", "with_human_verdict", "agree", "agree_pct", "human_yes_but_excluded", "human_no_but_included", "new_pairs_without_verdict"):
                n.append(_m(f"Human{cid}" + _camel(k), v[k]))
        n.append(_m("HumanTotalVerdicts", S["human_total_verdicts"]))
    sc = S["stratum_changed_under_802"]
    n.append(_m("StratumChanged", sc["changed"])); n.append(_m("StratumChangedOf", f"{sc['of']:,}"))
    (TEX / "numbers.tex").write_text("".join(n))

    # Table 1
    L = ["\\begin{tabular}{@{}llrr@{}}", "\\toprule", "ID & Finding & Setups & Collections \\\\", "\\midrule"]
    for cid, rule, fam, name in CATEGORIES:
        t = S["table1_pinned"][cid]
        L.append(f"{cid} & {name} ({fam}) & {t['setups']} ({t['setups_pct']}\\%) & {t['collections']} ({t['collections_pct']}\\%) \\\\")
    L.append("\\midrule")
    for key, lab in (("any_S", "Any security exposure (S)"), ("any_Q", "Any configuration issue (Q)"), ("any_P", "Any specification issue (P)"), ("any_six", "Any of the six")):
        t = S["table1_pinned"][key]
        L.append(f" & {lab} & {t['setups']} ({t['setups_pct']}\\%) & {t['collections']} ({t['collections_pct']}\\%) \\\\")
    L.append("\\midrule")
    t = S["table1_pinned"]["P3"]
    L.append(f"P3 & {t['name']} & {t['setups']} ({t['setups_pct']}\\%) & {t['collections']} ({t['collections_pct']}\\%) \\\\")
    L += ["\\bottomrule", "\\end{tabular}"]
    (TEX / "tab_categories.tex").write_text("\n".join(L) + "\n")

    # Table 2: ladder, both instruments
    lo, ln = S["ladder_old"], S["ladder_pinned"]
    L = ["\\begin{tabular}{@{}lrrrr@{}}", "\\toprule", "Analysis stage (setups, n = " + f"{S['corpus']['setups']:,}" + ") & \\multicolumn{2}{c}{7.15.0} & \\multicolumn{2}{c}{8.0.2} \\\\", "\\midrule",
         f"Any of the 31 candidate rules fired & {lo['raw31']} & {lo['raw31_pct']}\\% & {ln['raw31']} & {ln['raw31_pct']}\\% \\\\",
         f"Any of the six selected rules fired & {lo['raw6']} & {lo['raw6_pct']}\\% & {ln['raw6']} & {ln['raw6_pct']}\\% \\\\",
         f"Six rules, exposure or specification class only & {lo['class']} & {lo['class_pct']}\\% & {ln['class']} & {ln['class_pct']}\\% \\\\",
         f"Documented \\texttt{{find}}/\\texttt{{watch}} exception applied & {lo['nofind']} & {lo['nofind_pct']}\\% & {ln['nofind']} & {ln['nofind_pct']}\\% \\\\",
         f"Path exclusions and undetermined wrappers removed & {lo['final']} & {lo['final_pct']}\\% & {ln['final']} & {ln['final_pct']}\\% \\\\",
         "\\bottomrule", "\\end{tabular}"]
    (TEX / "tab_ladder.tex").write_text("\n".join(L) + "\n")

    # Table 3: instrument change
    L = ["\\begin{tabular}{@{}llrrrr@{}}", "\\toprule", "ID & Finding & 7.15.0 & 8.0.2 & Lost & Gained \\\\", "\\midrule"]
    for cid, v in S["instrument"].items():
        L.append(f"{cid} & {v['name']} & {v['old']} & {v['new']} & {v['lost']} & {v['gained']} \\\\")
    L += ["\\bottomrule", "\\end{tabular}"]
    (TEX / "tab_instrument.tex").write_text("\n".join(L) + "\n")

    # Table 4: persistence
    L = ["\\begin{tabular}{@{}llrrrrr@{}}", "\\toprule", "ID & Finding & At pin & Still & Resolved & Gone & New \\\\", "\\midrule"]
    for cid, v in S["persistence"].items():
        L.append(f"{cid} & {v['name']} & {v['flagged_at_pin']} & {v['still_at_head']} & {v['resolved_at_head']} & {v['repo_gone']} & {v['new_at_head']} \\\\")
    L += ["\\bottomrule", "\\end{tabular}"]
    (TEX / "tab_persistence.tex").write_text("\n".join(L) + "\n")

    # Table 5: MCP declarations
    d = md["setups"]
    L = ["\\begin{tabular}{@{}lr@{}}", "\\toprule", "MCP server declarations in setups & Count \\\\", "\\midrule",
         f"Declarations (files: {d.get('files', 0):,}) & {d.get('total', 0):,} \\\\",
         f"\\quad remote (URL) & {d.get('remote', 0):,} \\\\",
         f"\\quad local command or script & {d.get('local', 0) + d.get('other', 0):,} \\\\",
         f"\\quad package runner (npx, uvx, pipx, bunx, docker) & {d.get('package', 0):,} \\\\",
         f"\\qquad pinned (exact version or digest) & {d.get('package_pinned', 0):,} \\\\",
         f"\\qquad floating tag (\\texttt{{@latest}}, \\texttt{{:latest}}) & {d.get('package_tag', 0):,} \\\\",
         f"\\qquad no version & {d.get('package_unpinned', 0):,} \\\\",
         "\\bottomrule", "\\end{tabular}"]
    (TEX / "tab_declarations.tex").write_text("\n".join(L) + "\n")

    # Table 6: audit + human join
    if "audit_new" in S:
        L = ["\\begin{tabular}{@{}llrrrrr@{}}", "\\toprule", "ID & Finding & Findings & Re-derived & Refuted & Human-rated pairs & Agree \\\\", "\\midrule"]
        for cid, rule, fam, name in CATEGORIES:
            a = S["audit_new"][cid]
            h = S.get("human_join", {}).get(cid, {})
            L.append(f"{cid} & {name} & {a['findings']} & {a['confirmed']} & {a['refuted']} & {h.get('with_human_verdict', '--')}/{h.get('pairs_8_0_2', '--')} & {h.get('agree_pct', '--')}\\% \\\\")
        L += ["\\bottomrule", "\\end{tabular}"]
        (TEX / "tab_validation.tex").write_text("\n".join(L) + "\n")

    # grant classes
    L = ["\\begin{tabular}{@{}lrrrr@{}}", "\\toprule", "Grant class (repositories) & \\multicolumn{2}{c}{Settings (S2)} & \\multicolumn{2}{c}{Skills (S3)} \\\\",
         " & 7.15.0 & 8.0.2 & 7.15.0 & 8.0.2 \\\\", "\\midrule"]
    labels = [("unrestricted", "Unrestricted: \\texttt{Bash}, \\texttt{Bash(*)}"), ("arbitrary-exec", "Shell, interpreter, package runner, \\texttt{awk}/\\texttt{sed}"),
              ("stripped-wrapper", "Stripped wrapper (\\texttt{timeout}, \\texttt{xargs}, \\texttt{env}): undetermined"),
              ("prefix-excluded", "\\texttt{find}, \\texttt{watch}: not auto-approved (excluded)"),
              ("network", "Network tool (\\texttt{curl}, \\texttt{wget})"), ("indirect", "Container, build, remote (\\texttt{docker}, \\texttt{make}, \\texttt{ssh})"),
              ("bare-write-tool", "Bare \\texttt{Edit}/\\texttt{Write}/\\texttt{WebFetch}"), ("scoped", "Scoped shell or file-writing tool (skills)")]
    c2, c3 = S["classes"]["S2"], S["classes"]["S3"]
    for k, lab in labels:
        L.append(f"{lab} & {c2['old'].get(k, 0)} & {c2['new'].get(k, 0)} & {c3['old'].get(k, 0)} & {c3['new'].get(k, 0)} \\\\")
    L += ["\\bottomrule", "\\end{tabular}"]
    (TEX / "tab_grants.tex").write_text("\n".join(L) + "\n")


def figure(S: dict) -> None:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(7.2, 3.0), gridspec_kw={"width_ratios": [1.0, 1.6]})
    t = S["table1_pinned"]
    cats = ["S1", "S2", "S3", "P1", "Q1", "P2"]
    names = {c[0]: c[3] for c in CATEGORIES}
    old = [S["table1_old"][c]["setups_pct"] for c in cats]
    new = [t[c]["setups_pct"] for c in cats]
    y = range(len(cats))
    ax2.barh([i + 0.2 for i in y], old, height=0.38, color="#b0b0b0", label="7.15.0 (published)")
    ax2.barh([i - 0.2 for i in y], new, height=0.38, color="#1f4e79", label="8.0.2 (same commits)")
    ax2.set_yticks(list(y)); ax2.set_yticklabels([names[c].replace(" declaration", "").replace(" (settings)", "") for c in cats], fontsize=8)
    ax2.invert_yaxis(); ax2.set_xlabel("Setups with finding (%)", fontsize=8); ax2.tick_params(axis="x", labelsize=8)
    for i, (o, nw) in enumerate(zip(old, new)):
        ax2.text(max(o, nw) + 0.2, i, f"{o}% → {nw}%", va="center", fontsize=7)
    ax2.legend(fontsize=7, loc="lower right", frameon=False)
    ax2.set_xlim(0, max(max(old), max(new)) * 1.45)
    for s in ("top", "right"):
        ax2.spines[s].set_visible(False)
    xs = ["Setups\n(n = %s)" % f"{S['corpus']['setups']:,}", "Collections\n(n = %s)" % f"{S['corpus']['collections']:,}"]
    anyS = [t["any_S"]["setups_pct"], t["any_S"]["collections_pct"]]
    any6 = [t["any_six"]["setups_pct"], t["any_six"]["collections_pct"]]
    x = [0, 1]
    ax1.bar([i - 0.2 for i in x], anyS, width=0.38, color="#1f4e79", label="Any security exposure")
    ax1.bar([i + 0.2 for i in x], any6, width=0.38, color="#7fa6c9", label="Any of the six")
    for i in x:
        ax1.text(i - 0.2, anyS[i] + 0.3, f"{anyS[i]}%", ha="center", fontsize=7); ax1.text(i + 0.2, any6[i] + 0.3, f"{any6[i]}%", ha="center", fontsize=7)
    ax1.set_xticks(x); ax1.set_xticklabels(xs, fontsize=8); ax1.set_ylabel("Repositories in stratum (%)", fontsize=8); ax1.tick_params(axis="y", labelsize=8)
    ax1.legend(fontsize=7, frameon=False, loc="upper right"); ax1.set_ylim(0, max(any6 + anyS) * 1.35)
    for s in ("top", "right"):
        ax1.spines[s].set_visible(False)
    fig.tight_layout()
    FIG.mkdir(exist_ok=True)
    fig.savefig(FIG / "results_v802.png", dpi=200); fig.savefig(FIG / "results_v802.pdf")


if __name__ == "__main__":
    main()
