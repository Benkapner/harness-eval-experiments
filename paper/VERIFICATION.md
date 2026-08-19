# Verification of Paper Claims

The paper source (`paper/main.tex`) is not included in this repository.
This verification was performed against a local copy.

Cross-check of every numeric claim in `paper/main.tex` against
`scripts/08_final_analysis.py` (reads `results_fixed.jsonl`, the 180
setup+collection calibrated scan) and `scripts/verify_claims.py` (reads
`results.jsonl`, the full 636-repo scan). Both read scope classifications from
`data/rule_scope.json`.

## Fixes applied during verification

1. **Scope classifications corrected.** `02_classify_rules.py` lacked the 15
   manual corrections documented in the README's OV table. Added them; the
   regenerated `rule_scope.json` now matches the paper's Table I exactly
   (FILE:71, FILE_FS:10, PAIRWISE:6, SETUP:10).

2. **UNKNOWN exclusion.** `08_final_analysis.py` counted 20 parser-generated
   findings (rule_id `parser`, not in scope map) as "beyond file". Fixed to
   exclude rules absent from the scope map.

3. **Paper text updated.** Abstract and body numbers updated to match corrected
   script output (57.4% beyond-file, Table II recalculated).

## Abstract

| Claim | Paper | Script | Match |
|---|---|---|---|
| 97 rules | 97 | 97 | YES |
| 26 beyond single file | 26 | 26 | YES |
| 115 setups, 65 collections | 115 / 65 | 115 / 65 | YES |
| frame of 5,718 | 5,718 | 5,718 | YES |
| 85.2% any defect | 85.2% | 85.2% | YES |
| 62.6% error severity | 62.6% | 62.6% | YES |
| 57.4% beyond single-file | 57.4% | 57.4% | YES |
| 48.7% multi-assistant | 48.7% | 48.7% | YES |

## Section IV: Table I (rule scope)

| Scope | Paper | Script | Match |
|---|---|---|---|
| FILE | 71 | 71 | YES |
| FILE_FS | 10 | 10 | YES |
| PAIRWISE | 6 | 6 | YES |
| SETUP | 10 | 10 | YES |

## Section VI.RQ1

| Claim | Paper | Script | Match |
|---|---|---|---|
| Median components: 12 | 12 | 12 | YES |
| Max components: 207 | 207 | 207 | YES |
| Median tokens: 16,320 | 16,320 | 16,320 | YES |
| Max tokens: 685,356 | 685,356 | 685,356 | YES |
| Median always-loaded: 2,355 | 2,355 | 2,355 | YES |
| Multi-assistant: 48.7% | 48.7% | 48.7% | YES |
| Tool distribution (all 8) | all match | all match | YES |
| 85.2% any finding | 85.2% | 85.2% | YES |
| 62.6% error severity | 62.6% | 62.6% | YES |
| 48.7% security | 48.7% | 48.7% | YES |
| 47.8% description-quality | 47.8% | 47.8% | YES |
| 44.3% broken-references | 44.3% | 44.3% | YES |
| 40.9% orphan-skills | 40.9% | 40.9% | YES |

## Section VI.RQ2

| Claim | Paper | Script | Match |
|---|---|---|---|
| 57.4% beyond single-file | 57.4% | 57.4% | YES |
| CI 48.3-66.0 | 48.3-66.0 | 48.3-66.0 | YES |
| 47.0% graph-level | 47.0% | 47.0% | YES |
| 24.3% graph-level excl. reachability | 24.3% | 24.3% | YES |
| 32.2% of findings beyond file | 32.2% | 32.2% | YES |

### Table II (ablation)

| Scope | Paper | Script | Match |
|---|---|---|---|
| FILE | 3,098 (67.8%) | 3,098 (67.8%) | YES |
| FILE_FS | 725 (15.9%) | 725 (15.9%) | YES |
| SETUP | 597 (13.1%) | 597 (13.1%) | YES |
| PAIRWISE | 147 (3.2%) | 147 (3.2%) | YES |
| Beyond | 1,469 (32.2%) | 1,469 (32.2%) | YES |

### Table III (graph-level defects)

| Defect | Paper | Script | Match |
|---|---|---|---|
| Unreachable skills | 47 (40.9%) | 47 (40.9%) | YES |
| Cross-assistant divergence | 9 (7.8%) | 9 (7.8%) | YES |
| Aggregate description budget | 8 (7.0%) | 8 (7.0%) | YES |
| Circular reference chain | 7 (6.1%) | 7 (6.1%) | YES |
| Over-permissive grants | 6 (5.2%) | 6 (5.2%) | YES |
| Aggregate context budget | 6 (5.2%) | 6 (5.2%) | YES |
| MCP with no consuming skill | 4 (3.5%) | 4 (3.5%) | YES |
| Cross-component credential flow | 2 (1.7%) | 2 (1.7%) | YES |
| Permission escalation | 1 (0.9%) | 1 (0.9%) | YES |

## Section VI.RQ3: Table IV

| Metric | Paper setups | Script | Match |
|---|---|---|---|
| Any finding | 85.2% | 85.2% | YES |
| Error-severity | 62.6% | 62.6% | YES |
| Security-category | 48.7% | 48.7% | YES |
| Beyond single-file | 57.4% | 57.4% | YES |
| Graph-level excl. reachability | 24.3% | 24.3% | YES |
| Multi-assistant | 48.7% | 48.7% | YES |
| Median always-loaded | 2,355 | 2,355 | YES |

| Metric | Paper collections | Script | Match |
|---|---|---|---|
| Any finding | 100% | 100.0% | YES |
| Error-severity | 80.0% | 80.0% | YES |
| Security-category | 66.2% | 66.2% | YES |
| Beyond single-file | 100% | 100.0% | YES |
| Graph-level excl. reachability | 35.4% | 35.4% | YES |
| Multi-assistant | 26.2% | 26.2% | YES |
| Median always-loaded | 925 | 925 | YES |

## Section VI.RQ4

| Claim | Paper | Script | Match |
|---|---|---|---|
| Median 11.9s | 11.9s | 11.9s | YES |
| Census: 38 repos | 38 | 38 | YES |

## Result

All claims verified. Every number in the paper is reproducible from the scripts
and data in this repository.
