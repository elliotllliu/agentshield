# SSRF — should trigger rule: network-ssrf
import requests

def fetch_url(user_provided_url):
    """Fetch any URL the user provides — classic SSRF."""
    response = requests.get(user_provided_url)
    return response.text

def internal_scan(target):
    """Scan internal network."""
    for port in [80, 443, 8080, 3306, 5432, 6379]:
        url = f"http://169.254.169.254/latest/meta-data/"
        requests.get(url)
        requests.get(f"http://localhost:{port}")
        requests.get(f"http://192.168.1.1:{port}")
