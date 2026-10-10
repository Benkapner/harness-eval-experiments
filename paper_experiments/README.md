# Scanning the Harness: study artifact

Data, scripts, and figures for *Scanning the Harness: An Empirical Study of
Supply-Chain Defects in AI Coding-Agent Configurations*. Every number in the study
regenerates from the files in this directory with harness-eval **7.15.0**. Paper
TeX sources are not included in this tree.

## What was measured

3,171 public GitHub repositories that carry several harness files: 2,660 **setups**
(at least two component types, e.g. a context file with skills, or an MCP declaration
with settings) and 511 **collections** (five or more published skills). Every repository
is pinned to a commit; `data/repos.md` lists them with stars and a one-line description.

Thirty-one harness-eval rules were measured: rules whose condition is decidable from
the bytes of the configuration and whose consequence is a security exposure, a
configuration that cannot work as written, a departure from the Agent Skills
specification, or an inconsistency between two assistants' declarations.

## How every finding was validated

1. **Scan.** `scripts/scan.py` runs harness-eval on each repository at its pinned commit
   (`data/results.jsonl.gz`).
2. **Independent re-derivation.** `scripts/audit.py` re-clones each flagged repository and
   re-derives every finding with its own implementation of the rule's documented condition
   (`data/audit_findings.jsonl`, `data/audit_summary.json`; 8,547 findings across 1,115
   repositories).
3. **Adjudication of disagreements.** For every (repository, rule) pair on which the scanner
   and the re-derivation disagree, or whose consequence cannot be decided from bytes,
   `scripts/evidence.py` extracts the evidence and `scripts/adjudicate.py` asks a language
   model, with the prompt in the script and the API key from a local `.env`
   (see `.env.example`), for a verdict, a reason code, and a plain-language explanation
   (`data/adjudications.jsonl`). 744 pairs were re-derived; 586 agreed, 158 were adjudicated,
   640 count as defects.
4. **Independent second reading.** A separate model session, with no access to the audit or
   the adjudicator, re-read every counted pair against the repository and the current
   platform documentation (`data/defects_table_reviewed.csv`). `scripts/second_reader.py`
   scores it against the table (`data/second_reader_score.json`): 93.3% agreement, Cohen's
   kappa 0.76. Its rule-level objections were checked against the platform documentation
   and, where they held, became fixes in harness-eval 7.15.0 before the corpus was rescanned.

## Results

| | Setups | Collections |
|---|---|---|
| Repositories | 2,660 | 511 |
| Any confirmed security defect | 16.0% | 3.7% |
| Any configuration that cannot work as written | 0.8% | 0.0% |
| Any skill outside the Agent Skills specification | 2.4% | 3.5% |
| Any confirmed defect (security or cannot-work) | 16.7% | 3.7% |
| Any confirmed finding (all gating rules) | 18.4% | 6.8% |
| Raw output of the same rules before validation | 25.5% | 9.6% |

Per-rule agreement, pair counts, and adjudication outcomes are in `data/summary.json`
and `data/audit_summary.json`.

## Second iteration: harness-eval 8.0.2

The first iteration's own validation (mechanical re-derivation, model-assisted
adjudication, one author's review) consumed the scanner's output and could not
see two instrument defects: wildcard `find`/`watch` grants counted as arbitrary
execution although the client documents that a prefix rule does not auto-approve
them, and a `allowed-tools` parser that read only YAML lists and skipped the
specification's space-delimited string form. The second iteration fixes the
scanner (8.0.2), rescans the **same repositories at the same pinned commits**
(instrument change only), scans them again at the current default branch
(ecosystem change only), replaces model adjudication with a mechanical,
re-derivable inclusion policy (`scripts/reanalyze.py`), and joins the recorded
human verdicts to the new pairs.

| Path | Contents |
|---|---|
| `data/results_v802_pinned.jsonl` | 8.0.2 scan at the pinned commits; each record carries `head_now` and an `mcp_declarations` inventory (every server declaration by transport and pin state). |
| `data/results_v802_head.jsonl` | 8.0.2 scan at the default branch on the scan date. |
| `data/audit_findings_v802.jsonl`, `data/audit_summary_v802.json` | Mechanical re-derivation of the six headline rules on the pinned 8.0.2 scan; the audit encodes the documented `find`/`watch` exception. |
| `data/rules_v802.json` | The 8.0.2 rule catalog with effect, tier and scope. |
| `data/v802/summary.json`, `data/v802/tex/` | Every number of the second-iteration paper, the LaTeX tables and macros. |
| `figures/results_v802.{png,pdf}` | The second-iteration results figure. |

```bash
pip install harness-eval==8.0.2
make scan-pinned scan-head     # about five hours on four cores; resumable
make scan-retry                # re-scan the repositories that timed out, slowly
make audit-v802 reanalyze      # re-derivation of the six rules, then every table and macro
make paper-v802                # needs paper/main.tex (TeX sources are not in this tree)
```

The unit of analysis and the strata are fixed from the 7.15.0 scan, so every
table counts the same 2,660 setups and 511 collections. The published
7.15.0 pipeline (`scripts/analyze.py`, `scripts/adjudicate.py`) is unchanged and
still reproduces the first iteration's numbers.

## Layout

| Path | Contents |
|---|---|
| `figures/` | The results figure and the values it was drawn from. |
| `data/frame.jsonl`, `data/corpus_repos.txt` | The candidate list the scan reads, and the names of the corpus repositories. |
| `data/results.jsonl.gz` | Scan output per corpus repository: pinned commit, component inventory, findings. |
| `data/manifest.jsonl`, `data/repos.md`, `data/repo_descriptions.jsonl` | Per-repository URL, commit, stratum, discovery channel, rules fired; the human-readable table. |
| `data/rule_scope.json` | Every measured rule with its analysis scope (automated pass and hand review). |
| `data/audit_findings.jsonl`, `data/audit_summary.json` | The re-derivation verdict and sub-class for every finding, and per-rule agreement. |
| `data/evidence.jsonl`, `data/evidence_all.jsonl` | The evidence extracted for the adjudicated pairs (and for every re-derived pair). |
| `data/adjudications.jsonl` | The adjudicator's verdict, reason code, and plain-language explanation per pair. |
| `data/defects_table.{csv,xlsx}`, `data/defects_table_blind.csv`, `data/defects_table/` | Every re-derived pair with the harness file, the scanner's finding, the re-derivation result, the adjudicator's review, and a column for a verdict; a blind copy; one Markdown table per rule. |
| `data/defects_table_reviewed.csv`, `data/second_reader_score.json` | The independent second reading of every pair and its agreement with the table. |
| `data/reachability.json` | The seeded samples showing granted interpreters and unpinned servers are invoked by a component. |
| `data/candidate_funnel.json` | The counts the design section prints for how the corpus was arrived at. |
| `docs/FLOW_READING.md` | The reading behind the negative result on credential-to-network flow. |
| `scripts/` | The pipeline; `make help` lists the targets. |

## Reproducing

```bash
pip install harness-eval==7.15.0
cd paper_experiments
make audit evidence                 # re-clones the flagged repositories at their pinned commits
make adjudicate                     # needs ANTHROPIC_API_KEY; resumable, skips recorded pairs
make reach analyze verdicts
```

`make standalone` and `make paper` need the TeX sources (`paper/main.tex`). Those
files are not in this tree; `analyze.py` will recreate `paper/` locally if you run it.

`make scan` rescans the corpus from scratch with the installed harness-eval; it takes about an
hour with eight workers. No third-party repository content is stored here: the artifact consists
of URLs, pinned commits, findings, and the lines of evidence behind each adjudicated pair.
