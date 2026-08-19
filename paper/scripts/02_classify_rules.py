#!/usr/bin/env python3
"""Classify every harness-eval rule by the analysis scope its detection requires.

Scope is derived from what each rule class actually reads out of RuleContext
and the filesystem, not from documentation.

  FILE     decidable from the bytes of one component
  FILE_FS  needs the file plus the filesystem around it (path resolution)
  PAIRWISE needs at least two components compared to each other
  SETUP    needs the whole component graph / aggregate over all components
"""
from __future__ import annotations
import ast, json, pathlib, re, sys

RULES_DIR = pathlib.Path(sys.argv[1] if len(sys.argv) > 1
                         else "/home/claude/harness-eval/src/harness_eval/inspection/rules")

# signals, checked in priority order (most global wins)
SETUP_SIGNALS = [
    "component_graph", "reachable_from", "edges_from", "edges_to",
    "scan_state", "all_commands", "all_agents", "all_hooks",
    "mcp_servers", "settings", "compute_reachability", "discovered_",
]
PAIRWISE_SIGNALS = ["all_skills", "cosine", "tfidf", "TfidfVectorizer", "similarity"]
FS_SIGNALS = [".exists()", ".is_file()", ".is_dir()", "rglob", "glob(", "resolve()",
              "read_text", "iterdir", "os.path.exists", "os.walk"]


def rule_ids(path: pathlib.Path) -> list[str]:
    src = path.read_text(encoding="utf-8", errors="replace")
    return re.findall(r'id\s*=\s*["\']([a-z0-9\-]+/[a-z0-9\-]+)["\']', src)


def category_of(path: pathlib.Path) -> str:
    return path.parent.name


def classify(path: pathlib.Path) -> tuple[str, list[str]]:
    src = path.read_text(encoding="utf-8", errors="replace")
    body = src
    hits: list[str] = []
    scope = "FILE"
    for s in FS_SIGNALS:
        if s in body:
            hits.append(s)
            scope = "FILE_FS"
    for s in PAIRWISE_SIGNALS:
        if s in body:
            hits.append(s)
            scope = "PAIRWISE"
    for s in SETUP_SIGNALS:
        if s in body:
            hits.append(s)
            scope = "SETUP"
    return scope, sorted(set(hits))


OV = {
    "command/duplicate-detection":   ("PAIRWISE", "scan_state is cross-command similarity, not full graph"),
    "content/broken-references":     ("FILE_FS",  "uses scan_state only for project_root, resolves paths locally"),
    "content/duplicate-detection":   ("PAIRWISE", "scan_state is cross-skill similarity, not full graph"),
    "hooks/api-key-helper":          ("FILE",     "reads one hook definition, scan_state is incidental"),
    "hooks/base-url-override":       ("FILE",     "reads one hook definition, scan_state is incidental"),
    "hooks/env-credential-override": ("FILE",     "reads one hook definition, scan_state is incidental"),
    "hooks/no-audit-trail":          ("FILE",     "reads one hook definition, scan_state is incidental"),
    "hooks/no-commit-guard":         ("FILE",     "reads one hook definition, scan_state is incidental"),
    "hooks/pre-trust-permissions":   ("FILE",     "reads one hook definition, scan_state is incidental"),
    "hooks/script-boundary":         ("FILE_FS",  "resolves script paths relative to project dir"),
    "quality/redundant-guidance":    ("FILE",     "checks config presence but judgment is per-file"),
    "security/stealth-persistence":  ("FILE",     "reads one component, scan_state is incidental"),
    "content/hardcoded-machine-path":("FILE",     "iterates components for coverage but check is per-file"),
    "submission/file-completeness":  ("FILE",     "checks submission directory completeness, not graph"),
}


def main() -> None:
    rows = []
    for p in sorted(RULES_DIR.rglob("*.py")):
        if p.name.startswith("_") or p.name == "__init__.py":
            continue
        ids = rule_ids(p)
        if not ids:
            continue
        scope_auto, hits = classify(p)
        for rid in sorted(set(ids)):
            if rid in OV:
                scope, reason = OV[rid]
                rows.append({"rule_id": rid, "category": category_of(p),
                             "module": str(p.relative_to(RULES_DIR)),
                             "scope_auto": scope_auto, "scope": scope,
                             "signals": hits, "manually_corrected": True,
                             "correction_reason": reason})
            else:
                rows.append({"rule_id": rid, "category": category_of(p),
                             "module": str(p.relative_to(RULES_DIR)),
                             "scope_auto": scope_auto, "scope": scope_auto,
                             "signals": hits})
    out = pathlib.Path(__file__).resolve().parent.parent / "data" / "rule_scope.json"
    out.write_text(json.dumps(rows, indent=1))
    from collections import Counter
    c = Counter(r["scope"] for r in rows)
    print(f"{len(rows)} rules classified: {dict(c)}")
    for r in sorted(rows, key=lambda r: (r["scope"], r["rule_id"])):
        print(f'{r["scope"]:9} {r["rule_id"]:45} {",".join(r["signals"][:3])}')


if __name__ == "__main__":
    main()
