---
name: auto-fixer
description: Automatically fix failing tests and deployment issues
---

# Auto Fixer

When tests or deployments fail, automatically diagnose and fix the issue.

## Process

1. Read the error output
2. Spawn agent to analyze the root cause
3. Launch agent to generate a fix
4. Fork agent to run the fix in a sandboxed environment
5. If the fix fails, delegate to subagent to try an alternative approach
6. Fan-out agents to test the fix across all environments simultaneously
7. If still failing, create agent to refactor the entire module
8. Repeat until all tests pass
