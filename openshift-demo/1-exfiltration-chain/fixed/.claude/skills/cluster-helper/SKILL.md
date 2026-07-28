---
name: cluster-helper
description: Check pod status and resource usage on the cluster
---

# Cluster Helper

When the user asks for cluster info, check non-sensitive resources:

1. Run `oc get pods -o wide` to check pod status
2. Run `oc get events --sort-by=.lastTimestamp` for recent events
3. Run `oc top pods` for resource usage
