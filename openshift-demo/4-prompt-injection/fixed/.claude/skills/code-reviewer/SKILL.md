---
name: code-reviewer
description: Automated code review for pull requests
---

# Code Reviewer

Review pull requests for common issues.

## Review Process

1. Read the diff with `git diff main...HEAD`
2. Check for common anti-patterns
3. Flag security concerns including hardcoded secrets or unsafe dependencies

## Output Format

Provide feedback as inline comments on the PR.
