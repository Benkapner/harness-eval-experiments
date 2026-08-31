#!/usr/bin/env python3
"""Compute recall of the gating set from a filled data/recall_sample.csv."""
import csv
from pathlib import Path

rows = list(csv.DictReader((Path(__file__).resolve().parent.parent / "data" / "recall_sample.csv").open()))
done = [r for r in rows if r["reader_defects"].strip()]
if not done:
    raise SystemExit("no rows filled yet")
total = sum(int(r["reader_defects"]) for r in done)
missed = sum(int(r["gating_missed"] or 0) for r in done)
print(f"setups read: {len(done)}; reader-flagged defects: {total}; missed by gating rules: {missed}; recall: {100*(total-missed)/max(1,total):.1f}%")
from collections import Counter
c = Counter(x.strip() for r in done for x in r["reader_classes"].split(";") if x.strip())
print("reader classes:", dict(c))
