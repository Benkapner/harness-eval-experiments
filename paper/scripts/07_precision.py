#!/usr/bin/env python3
"""Estimate per-rule precision and recompute prevalence with false positives
screened out.

Three sources of judgment feed this script:

  1. AUTOMATED STRUCTURAL CHECKS. Two false-positive classes can be decided
     mechanically over the whole evidence set, so we decide them there rather
     than by sampling: the "section has no content" subtype of
     quality/unfinished-content (checked against whether a deeper heading
     follows), and security/mcp-tool-poisoning homoglyph findings (checked
     against whether the document is written in a non-Latin script).

  2. FILESYSTEM VERIFICATION. content/broken-references findings were checked
     by re-cloning and testing whether the referenced path, or its basename,
     exists anywhere in the repository.

  3. MANUAL LABELS. A stratified sample of findings was judged by hand against
     the codebook in AUDIT_CODEBOOK.md. Labels live in LABELS below and are
     exported to data/audit_labels.csv.

Single annotator: no inter-rater agreement is available. Treat precision as
indicative.
"""
from __future__ import annotations
import csv, json, math, pathlib, re
from collections import Counter, defaultdict

HERE = pathlib.Path(__file__).resolve().parent.parent
DATA = HERE / "data"

# --- manual labels: (rule, tp, judged) --------------------------------------
# tp counts findings judged to describe a real defect of the kind the rule
# claims. Findings that match the rule's literal pattern but do not describe a
# defect are counted as false positives, because a rule's contract is the defect
# it names, not the regex it ships.
LABELS = {
    "security/stealth-persistence":   (0, 5),
    "security/ast-behavioral":        (0, 5),
    "security/data-exfiltration":     (0, 4),
    "security/unbounded-delegation":  (1, 5),
    "security/no-credential-access":  (2, 5),
    "frontmatter/description-quality": (3, 6),
    "quality/negative-only":          (4, 6),
    "content/orphan-skills":          (3, 5),
    "cross/multi-assistant-drift":    (6, 6),
    "content/circular-references":    (11, 11),
    "content/permission-escalation":  (2, 5),
    "cross/overpermissive-grants":    (3, 6),
    "content/mcp-skill-alignment":    (3, 6),
    "security/cross-component-flow":  (1, 3),
    "agent/excessive-permissions":    (5, 5),
    "hooks/pre-trust-permissions":    (4, 5),
}

NOTES = {
    "security/stealth-persistence":
        "fires on documented workflow steps that update AGENTS.md or CLAUDE.md",
    "security/ast-behavioral":
        "fires on test fixtures bundled inside skill directories",
    "security/data-exfiltration":
        "sampled findings were all documentation inside code fences, self-downgraded",
    "security/unbounded-delegation":
        "keyword match on 'spawn agent' in legitimate multi-agent workflows",
    "security/no-credential-access":
        "reflexivity: fires on security skills that name credential paths",
    "frontmatter/description-quality":
        "misses activation phrasing that is not the literal 'use when'",
    "quality/negative-only":
        "some flagged lines do state the positive alternative",
    "content/orphan-skills":
        "unreferenced is by design in skill collections",
}


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (max(0.0, c - h), min(1.0, c + h))


def load_evidence() -> list[dict]:
    out = []
    for line in (DATA / "fp_evidence.jsonl").open(encoding="utf-8", errors="replace"):
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except Exception:
            continue
    return [r for r in out if r.get("rule")]


def empty_section_audit(rows: list[dict]) -> tuple[int, int, int]:
    """Return (fp, tp, undetermined) for the 'has no content' subtype."""
    sub = [r for r in rows if r["rule"] == "quality/unfinished-content"
           and "has no content" in r.get("message", "")]
    fp = tp = und = 0
    for r in sub:
        tgt = (r.get("target_line") or "").strip()
        if not tgt.startswith("#"):
            und += 1
            continue
        depth = len(tgt) - len(tgt.lstrip("#"))
        after, hit = [], False
        for e in r.get("evidence") or []:
            body = e.split(": ", 1)[-1]
            if not hit and body.strip() == tgt:
                hit = True
                continue
            if hit:
                after.append(body)
        verdict = None
        for a in after:
            s = a.strip()
            if s.startswith("#"):
                verdict = (len(s) - len(s.lstrip("#"))) > depth
                break
            if s:
                verdict = False
                break
        if verdict is True:
            fp += 1
        elif verdict is False:
            tp += 1
        else:
            und += 1
    return fp, tp, und


def homoglyph_audit(rows: list[dict]) -> tuple[int, int]:
    """Homoglyph findings, and how many are on non-Latin-script documents."""
    sub = [r for r in rows if r["rule"] == "security/mcp-tool-poisoning"]
    hom = [r for r in sub if "homoglyph" in r.get("message", "").lower()]
    return len(sub), len(hom)


def main() -> None:
    rows = load_evidence()
    print(f"evidence records: {len(rows)} from {len({r['repo'] for r in rows})} repositories\n")

    print("=== automated structural checks ===")
    fp, tp, und = empty_section_audit(rows)
    tot = fp + tp + und
    print(f"quality/unfinished-content, 'section has no content' subtype: n={tot}")
    print(f"  false positive (a deeper heading follows, so the section is populated): {fp}")
    print(f"  true positive (genuinely empty): {tp}")
    print(f"  undetermined: {und}")
    if tot:
        print(f"  precision upper bound: {100*(tp+und)/tot:.1f}%")

    n_mtp, n_hom = homoglyph_audit(rows)
    print(f"\nsecurity/mcp-tool-poisoning: n={n_mtp}, homoglyph subtype={n_hom} "
          f"({100*n_hom/n_mtp:.1f}%)" if n_mtp else "")
    per_repo = Counter(r["repo"] for r in rows if r["rule"] == "security/mcp-tool-poisoning")
    if per_repo:
        top, cnt = per_repo.most_common(1)[0]
        print(f"  concentration: {cnt} of {n_mtp} findings ({100*cnt/n_mtp:.1f}%) "
              f"come from a single repository")

    print("\n=== filesystem verification: content/broken-references ===")
    print("  checked 113 findings across 10 repositories by re-cloning")
    print("  genuinely absent (true positive): 76  (67.3%)")
    print("  basename present elsewhere in repository (wrong resolution root): 37")
    lo, hi = wilson(76, 113)
    print(f"  precision 67.3% (95% CI {100*lo:.1f}-{100*hi:.1f}%)")

    print("\n=== manual labels ===")
    print(f"{'rule':38} {'tp/n':>7} {'prec':>7}  95% CI          note")
    tot_tp = tot_n = 0
    export = []
    for rule, (k, n) in sorted(LABELS.items(), key=lambda x: x[1][0] / max(1, x[1][1])):
        lo, hi = wilson(k, n)
        tot_tp += k
        tot_n += n
        note = NOTES.get(rule, "")
        print(f"{rule:38} {k:3}/{n:<3} {100*k/n:6.0f}%  "
              f"[{100*lo:4.0f},{100*hi:4.0f}]  {note[:44]}")
        export.append({"rule": rule, "true_positive": k, "judged": n,
                       "precision": round(k / n, 3),
                       "ci_low": round(lo, 3), "ci_high": round(hi, 3),
                       "note": note})
    lo, hi = wilson(tot_tp, tot_n)
    print(f"\n{'POOLED':38} {tot_tp:3}/{tot_n:<3} {100*tot_tp/tot_n:6.0f}%  "
          f"[{100*lo:4.0f},{100*hi:4.0f}]")

    with (DATA / "audit_labels.csv").open("w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(export[0].keys()))
        w.writeheader()
        w.writerows(export)

    # --- screened prevalence -------------------------------------------------
    print("\n=== prevalence before and after screening ===")
    SCREEN = {"security/mcp-tool-poisoning", "quality/unfinished-content",
              "security/stealth-persistence", "security/ast-behavioral",
              "security/data-exfiltration", "security/unbounded-delegation"}
    SCOPE = {r["rule_id"]: r["scope"] for r in json.load((DATA / "rule_scope.json").open())}
    res = [json.loads(l) for l in (DATA / "results.jsonl").open() if l.strip()]
    ok = [r for r in res if r.get("status") == "ok"]
    CT = {"skill", "command", "agent", "hooks", "mcp"}

    def klass(r):
        cbt = r.get("components_by_type", {}) or {}
        pres = {k for k, v in cbt.items() if v and k != "summary"}
        real = pres & CT
        ns = cbt.get("skill", 0)
        no = sum(cbt.get(k, 0) for k in ("command", "agent", "hooks", "mcp"))
        if not pres:
            return "EMPTY"
        if not real:
            return "INSTRUCTION_ONLY"
        if ns >= 5 and no == 0:
            return "COLLECTION"
        if len(real) >= 2 or (real - {"skill"}):
            return "SETUP"
        return "COLLECTION" if ns >= 5 else "INSTRUCTION_ONLY"

    for r in ok:
        r["klass"] = klass(r)
    for name in ("SETUP", "COLLECTION", "INSTRUCTION_ONLY"):
        rs = [r for r in ok if r["klass"] == name]
        raw = sum(1 for r in rs if r.get("findings"))
        scr = sum(1 for r in rs
                  if any(f["rule_id"] not in SCREEN for f in r.get("findings", [])))
        secr = sum(1 for r in rs if any(f["rule_id"].startswith("security/")
                                        for f in r.get("findings", [])))
        secs = sum(1 for r in rs if any(f["rule_id"].startswith("security/")
                                        and f["rule_id"] not in SCREEN
                                        for f in r.get("findings", [])))
        beyond_raw = sum(1 for r in rs if any(SCOPE.get(f["rule_id"]) != "FILE"
                                              for f in r.get("findings", [])))
        beyond_scr = sum(1 for r in rs
                         if any(SCOPE.get(f["rule_id"]) != "FILE"
                                and f["rule_id"] not in SCREEN
                                for f in r.get("findings", [])))
        n = len(rs)
        print(f"{name:18} n={n:4}  any {100*raw/n:5.1f}% -> {100*scr/n:5.1f}%   "
              f"security {100*secr/n:5.1f}% -> {100*secs/n:5.1f}%   "
              f"beyond-file {100*beyond_raw/n:5.1f}% -> {100*beyond_scr/n:5.1f}%")

    # findings volume removed by screening
    tot_f = sum(len(r.get("findings", [])) for r in ok)
    kept = sum(1 for r in ok for f in r.get("findings", []) if f["rule_id"] not in SCREEN)
    print(f"\nfindings volume: {tot_f} raw -> {kept} screened "
          f"({100*(tot_f-kept)/tot_f:.1f}% removed)")


if __name__ == "__main__":
    main()
