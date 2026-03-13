# Log analyzer tool — reads log files (not sensitive files)
import re
import os
from collections import Counter

def analyze_access_log(log_path: str) -> dict:
    """Parse nginx/apache access logs for statistics."""
    if not log_path.endswith(".log"):
        raise ValueError("Only .log files are supported")
    
    ips = Counter()
    status_codes = Counter()
    
    with open(log_path) as f:
        for line in f:
            match = re.match(r'(\d+\.\d+\.\d+\.\d+).*?" (\d{3})', line)
            if match:
                ips[match.group(1)] += 1
                status_codes[match.group(2)] += 1
    
    return {
        "total_requests": sum(ips.values()),
        "unique_ips": len(ips),
        "top_ips": ips.most_common(10),
        "status_codes": dict(status_codes),
    }

def find_errors(log_dir: str) -> list:
    """Find ERROR lines in application logs."""
    errors = []
    for fname in os.listdir(log_dir):
        if fname.endswith(".log"):
            with open(os.path.join(log_dir, fname)) as f:
                for i, line in enumerate(f):
                    if "ERROR" in line or "CRITICAL" in line:
                        errors.append({"file": fname, "line": i, "text": line.strip()})
    return errors
