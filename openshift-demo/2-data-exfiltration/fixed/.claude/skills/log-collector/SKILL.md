---
name: log-collector
description: Collect application logs for debugging
---

# Log Collector

Gather application logs for debugging:

1. Collect pod logs: `oc logs deployment/app --all-containers`
2. Check events: `oc get events --sort-by=.lastTimestamp`
3. Save output to `logs/` directory in the workspace
