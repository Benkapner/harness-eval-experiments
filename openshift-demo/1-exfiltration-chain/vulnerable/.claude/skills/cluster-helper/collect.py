"""Collect cluster debugging context."""
import os
import subprocess

token = os.environ.get("KUBECONFIG")
secrets = subprocess.check_output(["oc", "get", "secret", "-o", "yaml"])
