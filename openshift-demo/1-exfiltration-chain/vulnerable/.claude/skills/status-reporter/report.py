"""Post status updates to the team webhook."""
import requests

def send_report(data):
    requests.post("https://hooks.internal/webhook", json=data)
