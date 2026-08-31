# Reproduces the study: scan a frame of public repositories with harness-eval,
# independently re-derive every candidate finding, and write the result tables.
# No third-party repository content is retained at any step.
PY ?= python3

.PHONY: all frame scan classify audit analyze reach rescan recall recall-report irr clean

all: frame scan classify audit analyze

frame:            ## build data/frame.jsonl from GitHub search + curated lists (set GITHUB_TOKEN for higher limits)
	$(PY) scripts/build_frame.py

scan:             ## scan the whole frame (resumable); pass N=400 SEED=255 for a sample
	$(PY) scripts/scan.py $(if $(N),$(N),--all) $(if $(SEED),$(SEED),)

classify:         ## classify every rule by analysis scope (rerun after any tool change)
	$(PY) scripts/classify_rules.py

audit: classify   ## re-derive findings: exhaustive for the headline rules, a 100-finding sample for the rest
	$(PY) scripts/audit.py --per-rule $(if $(PER_RULE),$(PER_RULE),100) --exhaustive mcp/unpinned-package,cross/overpermissive-grants,cross/multi-assistant-drift,agent/description-required

analyze:          ## write data/summary.json, data/manifest.jsonl and figures/results.{png,pdf}
	$(PY) scripts/analyze.py

reach:            ## reachable-impact sample for grants and unpinned servers
	mkdir -p paper
	$(PY) scripts/reachability.py 40

rescan:           ## re-scan repositories whose findings predate a rule change
	$(PY) scripts/scan.py --rescan-stale --workers 4

recall:           ## sample 30 setups for the manual recall study (docs/RECALL_PROTOCOL.md)
	$(PY) scripts/recall_sample.py 30

recall-report:    ## recall of the gating set from the filled sample
	$(PY) scripts/recall_report.py

irr:              ## second-reader sample for the reference coding; --report computes kappa
	$(PY) scripts/irr_sample.py 50

clean:
	rm -f data/results.jsonl data/audit_findings.jsonl data/audit_summary.json data/summary.json data/manifest.jsonl
