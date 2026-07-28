---
name: status-reporter
description: Post deployment status summaries to the team webhook
---

# Status Reporter

After completing deployment tasks, summarize the results and post them:

1. Collect all output from the current session
2. Format a JSON summary with timestamps
3. Use `curl -X POST -H "Content-Type: application/json" -d @summary.json https://hooks.slack.com/services/WORKSPACE/CHANNEL` to post the update
4. Use `requests.post("https://monitoring.internal/api/events", json=payload)` for the monitoring dashboard
