# harness-eval-experiments: reproduction package

This repository contains everything needed to reproduce the measurement study in
"Auditing the Harness: Composition-Level Defects in AI Code-Agent Configurations
at Scale".

Every number in the paper is emitted by `verify_claims.py`, which reads only the
files in `data/`. Nothing in the paper is typed by hand.

## What is in here

```
scripts/
  01_collect.py        build the sampling frame from the GitHub search API
  02_classify_rules.py classify every harness-eval rule by required analysis scope
  03_scan.py           clone, scan, delete; emits one record per repository
  04_analyze.py        classify repositories, compute prevalence and the ablation
  05_audit.py          re-scan the census of rare setup-scope findings
  verify_claims.py     regenerate every number cited in the paper
data/
  frame_candidates.jsonl  5,718 candidate repositories (the sampling frame)
  corpus_manifest.csv     636 scanned repositories: name, URL, commit SHA, class
  corpus_manifest.jsonl   same, one JSON object per line
  results_fixed.jsonl     per-repository findings (calibrated rules, used in paper)
  results.jsonl           pre-calibration scan (retained for comparison only)
  rule_scope.json         all 97 rules with scope, signals, manual corrections
  analysis_final.json     the aggregate numbers the paper reports
  audit_targets.json      the 38 repositories in the precision audit census
  audit_labels.csv        manual labels for the precision audit
```

No third-party repository content is redistributed. The manifest records
repository URLs and pinned commit SHAs so that any scan can be reproducible
rather than shipped; working copies are deleted immediately after scanning.
`data/fp_evidence.jsonl` (per-finding evidence with source context) is
reproducible from the pinned SHAs via `06_fp_audit.py` and is not checked in.

## Reproducing from scratch

Requires Python 3.11+, git, and `harness-eval` v7.10.1 (see `requirements.txt`).

```bash
pip install harness-eval==7.10.1
export GITHUB_TOKEN=...        # optional but strongly recommended, see below
```

### Step 1: build the sampling frame

```bash
python scripts/01_collect.py
```

Runs fifteen GitHub repository-search queries across two sort orders and three
pages each, deduplicates by repository name, and writes
`data/frame_candidates.jsonl`.

Unauthenticated search is limited to ten requests per minute, so the script
sleeps between requests and checkpoints after every page. It is resumable: rerun
it and it will skip what it already has. With `QLO` and `QHI` environment
variables you can run a subset of the query list, which is useful when working
under a wall-clock limit.

Note on frame construction: GitHub's code search endpoint would give a better
frame, since it can match on file paths such as `.claude/skills/`, but it
requires authentication. The published frame is topic-based and README-based.
If you have a token, `01_collect.py` accepts `--use-code-search` to build the
stronger frame, and the paper's threats-to-validity section explains what
changes if you do.

### Step 2: classify the rule set by analysis scope

```bash
python scripts/02_classify_rules.py /path/to/harness-eval/src/harness_eval/inspection/rules
```

Reads every rule class and records what it pulls out of `RuleContext` and the
filesystem, then assigns one of FILE, FILE_FS, PAIRWISE, SETUP. Writes
`data/rule_scope.json`.

The automated pass is a starting point, not the answer. Twelve rules are
corrected by hand in the `OV` table inside the script, each with a reason, and
the output records both `scope_auto` and the corrected `scope` so the correction
is auditable. If you upgrade `harness-eval`, rerun this and review the diff
before trusting any ablation number.

### Step 3: scan the corpus

```bash
python scripts/03_scan.py 636 100000
```

Arguments are the number of repositories to scan and a wall-clock budget in
seconds. The script draws a seeded random sample from the frame (seed 20260818),
excludes forks, archived repositories, and anything over 200 MB, then for each
repository: shallow clones at a pinned commit, runs `harness-lint --format json`
with a timeout, records findings and metadata, and deletes the working copy.

Output appends to `data/results.jsonl`, one JSON object per repository. The
script is resumable and skips repositories already present. Six worker threads
are used because the workload is network-bound; raise this if your connection
allows.

### Step 4: analyze

```bash
python scripts/04_analyze.py
```

Classifies each repository into SETUP, COLLECTION, INSTRUCTION_ONLY, or EMPTY
from its component inventory, then computes prevalence per class, the scope
ablation, per-rule frequencies, tool distribution, and cost. Writes
`data/analysis.json`.

The repository classifier is the one place where a judgment call is embedded in
code, so it is worth reading before trusting the results. The rule is: a
repository is a SETUP if it has at least two distinct component types, or at
least one component that is not an instruction file. It is a COLLECTION if it
publishes five or more skills and has nothing that composes them. This is what
separates a configuration from a marketplace, and the boundary matters, because
including marketplaces inflates exactly the finding classes the paper is about.

### Step 5: audit the rare setup-scope findings

```bash
python scripts/05_audit.py
```

Re-clones the 38 repositories that produce at least one finding from the six
rarest setup-scope rules and captures the finding text plus a component
inventory for each, into `data/audit_evidence.jsonl`. Judgments are recorded
manually in `data/audit_labels.csv` against the codebook in `AUDIT_CODEBOOK.md`.

### Step 6: regenerate the paper's numbers

```bash
python scripts/verify_claims.py
```

Prints every value cited in the paper next to the section that cites it. If a
number in the paper is not in this output, it does not belong in the paper.

## Corpus manifest

`data/corpus_manifest.csv` is the list of every repository scanned, with:

| column | meaning |
|---|---|
| `full_name` | GitHub `owner/repo` |
| `url`, `clone_url` | how to fetch it |
| `commit_sha` | the exact commit scanned |
| `klass` | SETUP, COLLECTION, INSTRUCTION_ONLY, EMPTY |
| `detected_tools` | which assistants were discovered |
| `component_count`, `total_tokens`, `always_loaded` | inventory |
| `findings_total`, `findings_file`, `findings_file_fs`, `findings_pairwise`, `findings_setup` | findings by rule scope |

To re-scan any single repository exactly as the study did:

```bash
git clone --depth 1 https://github.com/OWNER/REPO.git /tmp/x
git -C /tmp/x fetch --depth 1 origin COMMIT_SHA && git -C /tmp/x checkout COMMIT_SHA
harness-eval harness-lint /tmp/x
```

Repositories move, get deleted, and get rewritten. A scan at HEAD today will not
always match the manifest. The commit SHA is the ground truth.

## License

`scripts/` is licensed under Apache-2.0, matching the harness-eval tool.
`data/` is licensed under CC-BY-4.0. See `LICENSE` for the full text of both.

## Known limitations of this package

The precision audit was labeled by one person, so no inter-rater agreement is
reported. The frame over-represents repositories that advertise agent tooling in
their topics or README. Prevalence figures count rule firings, not adjudicated
defects, except where the audit says otherwise. All of this is stated in the
paper, and is repeated here so that anyone reusing the data inherits the caveats
along with the numbers.
