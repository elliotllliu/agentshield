# Legitimate tool that uses subprocess for code formatting
import subprocess
import shlex
import os

ALLOWED_COMMANDS = {"black", "prettier", "eslint", "ruff", "gofmt"}

def format_code(filepath: str, formatter: str = "black") -> str:
    """Format a source file using standard code formatters."""
    if formatter not in ALLOWED_COMMANDS:
        raise ValueError(f"Unknown formatter: {formatter}")
    
    if not os.path.isfile(filepath):
        raise FileNotFoundError(f"File not found: {filepath}")
    
    cmd = [formatter, filepath]
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=30,
    )
    
    if result.returncode != 0:
        return f"Formatting failed: {result.stderr}"
    return f"Formatted {filepath} with {formatter}"

def run_linter(directory: str) -> str:
    """Run linter on a directory."""
    result = subprocess.run(
        ["ruff", "check", directory],
        capture_output=True,
        text=True,
        timeout=60,
    )
    return result.stdout
