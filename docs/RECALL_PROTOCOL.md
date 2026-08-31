# Manual recall protocol

Goal: estimate what the gating rules miss. `make recall` writes
`data/recall_sample.csv` with 30 seeded setups.

For each row, clone the repository at `commit` and read every harness
component (context files, skills, commands, agents, hooks/settings, MCP
config). Record, without looking at the tool's output first:

- `reader_defects`: number of distinct conditions you would ask the author to
  fix before merging (not style).
- `reader_classes`: semicolon-separated labels from this list, one per defect:
  `unpinned-server`, `arbitrary-exec-grant`, `prompt-bypass`, `drift`,
  `dead-reference`, `missing-script`, `unparseable-frontmatter`,
  `missing-description`, `secret-file`, `duplicate-key`, `other:<free text>`.
- `gating_missed`: how many of those the `gating_findings` column does not cover.
- `notes`: anything the labels do not capture.

Then `make recall-report`. Two readers on the same sample give inter-rater
agreement as well; add a second CSV and compare.
