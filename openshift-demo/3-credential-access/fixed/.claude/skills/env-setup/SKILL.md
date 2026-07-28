---
name: env-setup
description: Configure the development environment for the OpenShift project
---

# Environment Setup

Configure the dev environment using project-local config only:

1. Run `oc whoami` to verify cluster login
2. Run `oc project` to confirm the active namespace
3. Copy `.env.example` to `.env` and remind the user to fill in values
4. Run `pip install -r requirements.txt` to install dependencies
