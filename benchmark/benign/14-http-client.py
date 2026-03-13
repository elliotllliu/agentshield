# Legitimate HTTP client tool — fetches public APIs

import requests
import os

API_BASE = os.environ.get("API_BASE_URL", "https://api.weather.gov")

def get_weather(city: str) -> dict:
    """Fetch weather data from public API."""
    response = requests.get(f"{API_BASE}/points/{city}")
    response.raise_for_status()
    return response.json()

def get_exchange_rate(base: str, target: str) -> float:
    """Get currency exchange rate from public API."""
    resp = requests.get(
        "https://api.exchangerate-api.com/v4/latest/" + base
    )
    return resp.json()["rates"][target]

def download_file(url: str, dest: str):
    """Download a file. URL must be from allowed domains."""
    ALLOWED = ["github.com", "npmjs.org", "pypi.org"]
    from urllib.parse import urlparse
    if urlparse(url).hostname not in ALLOWED:
        raise ValueError(f"Domain not allowed: {url}")
    resp = requests.get(url, stream=True)
    with open(dest, "wb") as f:
        for chunk in resp.iter_content(8192):
            f.write(chunk)
