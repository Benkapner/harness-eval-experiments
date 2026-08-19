# harness-eval-experiments

Reproduction package for a research paper on auditing AI code-agent
configurations. The paper source is in `paper/main.tex`.

## What this repository is

A measurement pipeline, not a library. `scripts/` runs in numeric order:
frame construction, rule scope classification, scanning, analysis, evidence
capture, precision, final numbers. `data/` holds the outputs. Every number in
the paper is emitted by a script here.

## Invariants

These are not style preferences. Breaking any of them invalidates the paper.

- **No hand-typed numbers.** Anything that reaches `paper/main.tex` must be
  produced by a script in `scripts/`. If a value cannot be regenerated, it does
  not belong in the paper. `verify_claims.py` and `08_final_analysis.py` are the
  source of truth.
- **No third-party repository content in `data/`.** Manifests carry repository
  URLs and commit SHAs. Scanned working copies are deleted immediately. This is
  what makes the artifact redistributable.
- **Scans are pinned.** Reproducing a finding means checking out the recorded
  commit SHA, not HEAD. Repositories in this population move constantly.
- **Scripts stay resumable and seeded.** Sampling uses a fixed seed; collection
  and scanning skip work already recorded. Long runs happen in bounded batches.
- **A tool change invalidates the scope classification.** If `harness-eval` is
  upgraded, rerun `02_classify_rules.py` and review the diff before trusting any
  downstream result. The paper's central claim rests on which rules require
  which analysis scope.

## Reading the data

Several files are large. Query them, do not open them.

| File | Size | Lines |
|---|---|---|
| `data/fp_evidence.jsonl` | 13 MB | 4,937 |
| `data/frame_candidates.jsonl` | 2.7 MB | 5,718 |
| `data/results.jsonl` | 1.5 MB | 636 |
| `data/results_fixed.jsonl` | 1.2 MB | 180 |
| `data/corpus_manifest.csv` | 144 KB | 636 |

`results_fixed.jsonl` is the scan behind the paper, produced with the calibrated
rule set. `results.jsonl` is the earlier scan, retained for comparison only; do
not mix them.

Small enough to read directly: `analysis_final.json`, `rule_scope.json`,
`audit_targets.json`, `audit_labels.csv`, `AUDIT_CODEBOOK.md`.

## Judging findings

`AUDIT_CODEBOOK.md` defines what counts as a correct finding: a finding is
correct when it identifies a real instance of the defect the rule names, not
when it matches the pattern the rule ships. Labeling is done by a human. Do not
label findings; prepare them with surrounding source for a human to judge.

## Environment

Python 3.11+, git, and `harness-eval` v7.10.1 installed. Confirm the version
before running anything, because v7.10.0 produces different numbers for three
rules.
