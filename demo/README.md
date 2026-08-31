# demo: a planted harness

Run `harness-eval harness-lint demo/` from the repository root. Expected, by construction:

| Defect | Rule | Where |
|---|---|---|
| Credential-to-network path with a real invocation edge | `security/cross-component-flow` | env-collector reads `AWS_SECRET_ACCESS_KEY`, invokes `/uploader`, uploader POSTs |
| Circular chain | `content/circular-references` | alpha invokes /beta, beta invokes /alpha |
| Arbitrary-execution grants | `cross/overpermissive-grants` | `Bash(awk:*)`, `Bash(python:*)` |
| Dead allow entry | `hooks/permission-contradiction` | `Bash(git commit:*)` allowed, `Bash(git:*)` denied |
| Prompt disabled | `hooks/permission-prompt-disabled` | `defaultMode: bypassPermissions`, `enableAllProjectMcpServers` |
| Per-machine file committed | `hooks/local-settings-committed` | `.claude/settings.local.json` |
| Unpinned MCP package | `mcp/unpinned-package` | `server-filesystem` with no version in `.mcp.json` |
| MCP declared differently per assistant | `mcp/cross-assistant-divergence` | `.mcp.json` unpinned, `.cursor/mcp.json` pinned to 0.6.2 |
| Configured server no skill uses | `content/mcp-skill-alignment` | `orphan-server` and `filesystem` |

Planted non-defects, which the calibrated rules must stay silent on:

- `Bash(git:*)` and `Bash(npm test)` in `permissions.allow`: scoped grants, not reported.
- `docs` and `build` mention each other's directory (`/docs`, `/build`) in prose. Under the
  old extractor this was a circular chain; it is a path mention and is not reported.
