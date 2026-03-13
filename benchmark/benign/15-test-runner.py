# Legitimate test runner with eval for test assertions
import json

def evaluate_expression(expr: str, context: dict) -> bool:
    """Evaluate a test assertion expression.
    
    Only allows simple comparison expressions for test assertions.
    """
    # Restricted eval for test assertions only
    allowed_names = {"True": True, "False": False, "None": None}
    allowed_names.update(context)
    return eval(expr, {"__builtins__": {}}, allowed_names)

def run_tests(test_file: str):
    """Run test cases from a JSON file."""
    with open(test_file) as f:
        tests = json.load(f)
    
    results = []
    for test in tests:
        actual = test["function"](**test["args"])
        passed = actual == test["expected"]
        results.append({"name": test["name"], "passed": passed})
    
    return results
