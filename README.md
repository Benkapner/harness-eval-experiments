# harness-eval-experiments

Regression test fixtures for [harness-eval](https://github.com/redhat-community-ai-tools/harness-eval). Each scenario has a `vulnerable/` and `fixed/` setup to verify detection works.

## Scenarios

| # | Scenario | What the vulnerable setup does |
|---|----------|-------------------------------|
| 1 | Exfiltration chain | Two skills form a credential-to-network pipeline |
| 2 | Data exfiltration | Skill sends local files to an external server |
| 3 | Credential access | Skill reads SSH keys and AWS credentials |
| 4 | Prompt injection | Skill overrides system instructions |
| 5 | Obfuscation | Base64-encoded payload hides real behavior |
| 6 | Coercive override | Skill forces the agent to bypass safety checks |
| 7 | Unbounded delegation | Skill spawns unlimited subagents |

## Automated regression

The `regression.yml` workflow runs weekly (Monday 6am UTC) and on manual trigger. It installs the latest `harness-eval` from PyPI, scans each scenario, and asserts:

- Vulnerable setups get **UNSAFE**
- Fixed setups get **SAFE** or **CAUTION**

To test a specific version:

```
gh workflow run regression.yml -f harness_eval_version=7.6.0
```

## Local testing

```bash
pip install harness-eval
harness-eval scan openshift-demo/1-exfiltration-chain/vulnerable   # should be UNSAFE
harness-eval scan openshift-demo/1-exfiltration-chain/fixed         # should be SAFE
```
