#!/usr/bin/env python3
"""Sample setups for a manual full-inspection recall study.

Writes data/recall_sample.csv: N seeded setups with URL and pinned commit,
what the gating rules found, and empty columns for the reader. Protocol in
docs/RECALL_PROTOCOL.md. After the reading, `make recall-report` computes the
share of reader-flagged defects the gating rules also found (recall) and the
classes they missed.
"""
from __future__ import annotations

import csv
import json
import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data"
N = int(sys.argv[1]) if len(sys.argv) > 1 else 30
GATING = ["mcp/unpinned-package", "cross/overpermissive-grants", "cross/multi-assistant-drift", "agent/description-required"]

sys.path.insert(0, str(ROOT / "scripts"))
from analyze import stratum  # noqa: E402

recs = [json.loads(l) for l in (DATA / "results.jsonl").read_text().splitlines() if l.strip()]
setups = [r for r in recs if r.get("status") == "ok" and stratum(r) == "SETUP"]
random.Random(255).shuffle(setups)
rows = []
for r in setups[:N]:
    found = sorted({f["rule"] for f in r["findings"] if f["rule"] in GATING})
    rows.append({"url": r["url"], "commit": r["commit"], "components": r["inventory"]["component_count"],
                 "gating_findings": ";".join(found),
                 "reader_defects": "", "reader_classes": "", "gating_missed": "", "notes": ""})
out = DATA / "recall_sample.csv"
with out.open("w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
    w.writeheader(); w.writerows(rows)
print(f"wrote {out} ({len(rows)} setups). Read each repository at its commit and fill reader_* columns; see docs/RECALL_PROTOCOL.md")
