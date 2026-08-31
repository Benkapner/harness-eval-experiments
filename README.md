# harness-eval-experiments

Measurement study and regression fixtures for
[harness-eval](https://github.com/redhat-community-ai-tools/harness-eval), a
linter for AI coding-agent configurations (`.claude/`, `CLAUDE.md`, skills,
hooks, MCP servers, and their cross-tool equivalents).

This repository holds two things:

- **`scripts/` + `data/` + `figures/`** — a reproducible study that scans a
  frame of public repositories with `harness-eval`, independently re-derives
  every candidate finding at its pinned commit, and reports prevalence and
  audited precision.
- **`openshift-demo/`** — seven hand-built vulnerable/fixed scenarios used by
  the weekly regression workflow (`.github/workflows/regression.yml`) to assert
  that `harness-eval` still detects (and does not over-flag) known patterns.

## The study

The pipeline runs end to end with `make all` and keeps **no third-party
repository content**: every working copy is shallow-cloned, scanned, and
deleted; the manifests carry only URLs and commit identifiers.

| Stage | Script | What it does |
|---|---|---|
| frame | `scripts/build_frame.py` | Builds the repository frame from GitHub topic search, README search, and public awesome-lists. Records the discovery channel per repository. |
| scan | `scripts/scan.py` | Shallow-clones each repository, records the commit, runs `harness-eval harness-lint --format json`, records inventory and findings, deletes the clone. Resumable. |
| classify | `scripts/classify_rules.py` | Classifies every rule by analysis scope (FILE, FILE_FS, PAIRWISE, SETUP) from its implementation, with a recorded override table. |
| audit | `scripts/audit.py` | Re-clones flagged repositories at their pinned commit and re-derives every candidate finding with an independent check. Headline rules are audited exhaustively. |
| analyze | `scripts/analyze.py` | Assigns strata, computes prevalence with Wilson intervals and the scope ablation, and writes `data/summary.json` and `figures/results.{png,pdf}`. |
| reach | `scripts/reachability.py` | Reachable-impact sample for grants and unpinned MCP servers. |
| recall | `scripts/recall_sample.py` | Seeded sample of setups for a manual recall protocol (`docs/RECALL_PROTOCOL.md`). |
| irr | `scripts/irr_sample.py` | Second-reader sample for the broken-reference consequence coding. |

```bash
pip install harness-eval==7.11.0  # version recorded in data/results.jsonl
make all                          # frame -> scan -> classify -> audit -> analyze
```

`scan.py` and `audit.py` skip work already recorded, so an interrupted run
resumes. All scripts are seeded (default seed 255). To reproduce the committed
numbers, use the files under `data/` rather than re-scanning.

## Results (committed run)

- **2,428** repositories scanned with harness-eval **7.11.0** (2,380 clean
  lints; 39 timeouts, 8 clone failures, 1 lint failure).
- Strata: **EMPTY 714**, **INSTRUCTION_ONLY 611**, **SETUP 853** (of which
  **669** assembled), **COLLECTION 202**.
- **244** flagged repositories (**1,067** findings) re-audited at their pinned
  commit. Headline rules were audited exhaustively. Most reported rules
  confirmed at 100% precision, e.g. `mcp/unpinned-package` 130/130,
  `cross/overpermissive-grants` 114/114, `content/hardcoded-machine-path`
  98/98. `content/orphan-skills` was the notable low-precision rule
  (5/127 confirmed) and drove calibration work in the tool.

Committed artifacts:

| Path | Contents |
|---|---|
| `data/frame.jsonl` | The repository frame (URLs + discovery channel). |
| `data/manifest.jsonl` | One line per scanned repository: URL, pinned commit, stratum, channels, finding counts by scope. No repository content. |
| `data/results.jsonl` | Raw per-repository lint output for the scan. |
| `data/audit_findings.jsonl`, `data/audit_summary.json` | Independent re-derivation of each candidate finding. |
| `data/summary.json` | Strata, prevalence, scope ablation, per-rule counts. |
| `data/rule_scope.json` | Per-rule analysis-scope classification with overrides. |
| `data/reachability.json` | Reachable-impact sample. |
| `data/irr_sample.csv`, `data/recall_sample.csv` | Protocol samples; second-reader / recall columns are blank until filled. |
| `figures/results.{png,pdf}` | Prevalence figure. |
| `demo/` | Planted harness where every listed defect is a true positive by construction. |

## Constraints

- No third-party repository content is retained or redistributed.
- Every scan is pinned to a commit; every audit re-clones that commit.
- A change to the tool invalidates `data/rule_scope.json`; rerun
  `make classify` and review the diff before trusting anything downstream.
