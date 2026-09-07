# harness-eval-experiments

Measurement study and regression fixtures for
[harness-eval](https://github.com/redhat-community-ai-tools/harness-eval), a
linter for AI coding-agent configurations.

- **`paper_experiments/`** — study artifact for *Scanning the Harness* (corpus,
  audit data, scripts, figures). Paper TeX sources are not in this tree. See
  [`paper_experiments/README.md`](paper_experiments/README.md).
- **`openshift-demo/`** — seven hand-built vulnerable/fixed scenarios used by
  the weekly regression workflow (`.github/workflows/regression.yml`).
- **`demo/`** — a planted harness where listed defects are true positives by
  construction.

```bash
pip install harness-eval==7.15.0
cd paper_experiments
make help
```
