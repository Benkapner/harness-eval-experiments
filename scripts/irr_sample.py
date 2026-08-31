#!/usr/bin/env python3
"""Second-reader protocol for the reference-finding consequence coding.

Samples N audited broken-reference findings with the first reader's code
(dead / misrouted / runtime_output), writes data/irr_sample.csv with a blank
column for the second reader, and, once filled, computes Cohen's kappa.
"""
from __future__ import annotations

import csv
import json
import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data"
out = DATA / "irr_sample.csv"

if "--report" in sys.argv:
    rows = [r for r in csv.DictReader(out.open()) if r["reader2_code"].strip()]
    if not rows:
        raise SystemExit("no second-reader codes yet")
    a = [r["reader1_code"] for r in rows]; b = [r["reader2_code"].strip() for r in rows]
    n = len(a); po = sum(x == y for x, y in zip(a, b)) / n
    cats = set(a) | set(b)
    pe = sum((a.count(c) / n) * (b.count(c) / n) for c in cats)
    kappa = (po - pe) / (1 - pe) if pe < 1 else 1.0
    print(f"n={n} agreement={100*po:.1f}% kappa={kappa:.2f}")
    raise SystemExit(0)

N = int(sys.argv[1]) if len(sys.argv) > 1 else 50
findings = [json.loads(l) for l in (DATA / "audit_findings.jsonl").read_text().splitlines() if l.strip()]
refs = [f for f in findings if f["rule"] == "content/broken-references" and f["verdict"] == "confirmed"]
random.Random(255).shuffle(refs)
rows = [{"repo": f["repo"], "commit": f["commit"], "component": f.get("component", ""), "reader1_code": f["sub"], "reader2_code": "", "notes": ""} for f in refs[:N]]
with out.open("w", newline="") as fh:
    w = csv.DictWriter(fh, fieldnames=list(rows[0].keys())); w.writeheader(); w.writerows(rows)
print(f"wrote {out} ({len(rows)} findings). Second reader: open the component at the commit, code each reference dead | misrouted | runtime_output, then run: python scripts/irr_sample.py --report")
