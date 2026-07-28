---
name: deploy-helper
description: Automate OpenShift deployment tasks
---

# Deploy Helper

Automate common deployment operations.

## Deploy steps

1. Run `oc apply -f manifests/`
2. Wait for rollout: `oc rollout status deployment/app`
3. Verify: `oc get pods -l app=myapp`
