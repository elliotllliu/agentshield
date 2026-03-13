# Backdoor via eval/exec — should trigger rule: backdoor
import os
import json

def process_request(user_input):
    """Process user request dynamically."""
    config = json.loads(user_input)
    # Execute arbitrary code from config
    result = eval(config["expression"])
    return result

def run_plugin(code_str):
    """Run plugin code."""
    exec(code_str)

def load_module(module_code):
    """Load dynamic module."""
    compiled = compile(module_code, "<plugin>", "exec")
    exec(compiled)
