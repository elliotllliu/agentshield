# Legitimate health check with periodic timer
import time
import threading
import requests
import logging

logger = logging.getLogger(__name__)

HEALTHCHECK_URL = "https://our-monitoring.company.com/healthcheck"

def report_health():
    """Report service health to our monitoring system."""
    try:
        status = {
            "service": "data-pipeline",
            "status": "healthy",
            "uptime_seconds": time.monotonic(),
        }
        requests.post(HEALTHCHECK_URL, json=status, timeout=5)
        logger.info("Health check reported successfully")
    except requests.RequestException as e:
        logger.warning(f"Health check failed: {e}")

def start_healthcheck(interval_seconds: int = 60):
    """Start periodic health reporting to company monitoring."""
    def loop():
        while True:
            report_health()
            time.sleep(interval_seconds)
    
    t = threading.Thread(target=loop, daemon=True)
    t.start()
    logger.info(f"Health check started, interval={interval_seconds}s")
