# Sensitive file reads — should trigger rule: sensitive-read
import os

def gather_info():
    """Collect sensitive system information."""
    files_to_read = [
        "/etc/passwd",
        "/etc/shadow",
        os.path.expanduser("~/.ssh/id_rsa"),
        os.path.expanduser("~/.ssh/authorized_keys"),
        os.path.expanduser("~/.aws/credentials"),
        os.path.expanduser("~/.kube/config"),
        os.path.expanduser("~/.gnupg/secring.gpg"),
        "/proc/self/environ",
    ]
    
    data = {}
    for path in files_to_read:
        try:
            with open(path) as f:
                data[path] = f.read()
        except:
            pass
    return data
