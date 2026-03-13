#!/usr/bin/env python3
"""
AgentShield Python AST Analyzer

Performs deep AST-based analysis of Python files to detect security issues
with much higher precision than regex matching.

Key advantages over regex:
- Distinguishes function calls from strings/comments
- Tracks data flow (taint analysis lite)
- Identifies eval/exec with literal vs dynamic arguments
- Detects monkey-patching and dynamic attribute access
- Zero false positives on pattern definitions and string constants

Usage: python3 ast_analyzer.py <file_path>
Output: JSON array of findings
"""

import ast
import json
import sys
import os
from typing import Any


class SecurityVisitor(ast.NodeVisitor):
    """AST visitor that detects security-relevant patterns."""

    def __init__(self, filename: str):
        self.filename = filename
        self.findings: list[dict] = []
        self.tainted_vars: set[str] = set()  # Variables from user input
        self.dangerous_calls: set[str] = set()
        self.imports: dict[str, str] = {}  # alias -> module

    def _add(self, node: ast.AST, severity: str, rule: str, message: str,
             confidence: str = "high"):
        self.findings.append({
            "line": getattr(node, "lineno", 0),
            "severity": severity,
            "rule": rule,
            "message": message,
            "confidence": confidence,
            "file": self.filename,
        })

    # === Import tracking ===
    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            name = alias.asname or alias.name
            self.imports[name] = alias.name
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        module = node.module or ""
        for alias in node.names:
            name = alias.asname or alias.name
            self.imports[name] = f"{module}.{alias.name}"
        self.generic_visit(node)

    # === Dangerous function calls ===
    def visit_Call(self, node: ast.Call):
        func_name = self._get_call_name(node)

        # eval() / exec() with non-literal argument
        if func_name in ("eval", "exec", "builtins.eval", "builtins.exec"):
            if node.args and not self._is_safe_literal(node.args[0]):
                is_tainted = self._is_tainted(node.args[0])
                sev = "high" if is_tainted else "medium"
                conf = "high" if is_tainted else "medium"
                self._add(node, sev, "ast-code-exec",
                          f"{func_name}() with {'tainted' if is_tainted else 'dynamic'} input — code execution risk",
                          conf)

        # compile() — often precedes exec
        if func_name == "compile":
            if node.args and not self._is_safe_literal(node.args[0]):
                self._add(node, "medium", "ast-code-exec",
                          "compile() with dynamic input — may enable code execution",
                          "medium")

        # subprocess / os.system / os.popen
        if func_name in ("os.system", "os.popen", "os.exec",
                          "subprocess.call", "subprocess.run",
                          "subprocess.Popen", "subprocess.check_output",
                          "subprocess.check_call"):
            if node.args and not self._is_safe_literal(node.args[0]):
                is_tainted = self._is_tainted(node.args[0])
                sev = "high" if is_tainted else "medium"
                self._add(node, sev, "ast-cmd-injection",
                          f"{func_name}() with {'tainted' if is_tainted else 'dynamic'} input — command injection risk",
                          "high" if is_tainted else "medium")

        # pickle.loads — deserialization
        if func_name in ("pickle.loads", "pickle.load",
                          "marshal.loads", "marshal.load",
                          "shelve.open", "yaml.load", "yaml.unsafe_load"):
            unsafe_yaml = func_name == "yaml.load" and not self._has_safe_loader(node)
            if func_name != "yaml.load" or unsafe_yaml:
                self._add(node, "high", "ast-deserialization",
                          f"{func_name}() — insecure deserialization, arbitrary code execution possible",
                          "high")

        # SQL injection via string formatting
        if func_name in ("cursor.execute", "execute", "executemany"):
            if node.args and self._is_formatted_string(node.args[0]):
                self._add(node, "high", "ast-sql-injection",
                          "SQL query with string formatting — SQL injection risk",
                          "high")

        # __import__ — dynamic import
        if func_name == "__import__":
            if node.args and not self._is_safe_literal(node.args[0]):
                self._add(node, "medium", "ast-dynamic-import",
                          "__import__() with dynamic module name",
                          "medium")

        # getattr with dynamic attribute — can bypass restrictions
        if func_name == "getattr":
            if len(node.args) >= 2 and not self._is_safe_literal(node.args[1]):
                self._add(node, "medium", "ast-dynamic-attr",
                          "getattr() with dynamic attribute name — potential restriction bypass",
                          "medium")

        # Taint tracking: mark return values of input functions as tainted
        if func_name in ("input", "request.form.get", "request.args.get",
                          "request.json.get"):
            # If this is assigned, track the variable
            pass  # Handled in visit_Assign

        self.generic_visit(node)

    # === Assignment tracking for taint analysis ===
    def visit_Assign(self, node: ast.Assign):
        # Track tainted variables (from user input sources)
        if isinstance(node.value, ast.Call):
            func_name = self._get_call_name(node.value)
            input_funcs = {"input", "request.form.get", "request.args.get",
                           "request.json.get", "request.data",
                           "sys.argv", "os.environ.get", "os.getenv"}
            if func_name in input_funcs:
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        self.tainted_vars.add(target.id)

        # Track subscript access on known tainted sources
        if isinstance(node.value, ast.Subscript):
            source = self._get_source_name(node.value.value)
            if source in ("request.form", "request.args", "request.json",
                           "request.data", "os.environ", "sys.argv",
                           "request.headers"):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        self.tainted_vars.add(target.id)

        self.generic_visit(node)

    # === Dangerous patterns ===
    def visit_Attribute(self, node: ast.Attribute):
        # Detect monkey-patching of security-sensitive attributes
        if isinstance(node.ctx, ast.Store):
            if node.attr in ("verify", "check_hostname"):
                self._add(node, "medium", "ast-ssl-bypass",
                          f"Overwriting '{node.attr}' — potential SSL/TLS verification bypass",
                          "medium")
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef):
        # Detect functions with suspicious names that take user input
        suspicious = {"execute", "run_code", "run_command", "shell",
                      "execute_command", "eval_code", "run_script"}
        if node.name.lower() in suspicious:
            self._add(node, "medium", "ast-dangerous-func",
                      f"Function '{node.name}' has suspicious name suggesting code execution",
                      "low")
        self.generic_visit(node)

    # === Helper methods ===
    def _get_call_name(self, node: ast.Call) -> str:
        """Get the full dotted name of a function call."""
        if isinstance(node.func, ast.Name):
            # Resolve imports
            name = node.func.id
            return self.imports.get(name, name)
        elif isinstance(node.func, ast.Attribute):
            parts = []
            current: ast.expr = node.func
            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                parts.append(self.imports.get(current.id, current.id))
            return ".".join(reversed(parts))
        return ""

    def _get_source_name(self, node: ast.expr) -> str:
        """Get dotted name of an expression."""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            parent = self._get_source_name(node.value)
            return f"{parent}.{node.attr}" if parent else node.attr
        return ""

    def _is_safe_literal(self, node: ast.expr) -> bool:
        """Check if an expression is a safe literal (string/number/dict/list constant)."""
        if isinstance(node, ast.Constant):
            return True
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            return all(self._is_safe_literal(elt) for elt in node.elts)
        if isinstance(node, ast.Dict):
            return (all(self._is_safe_literal(k) for k in node.keys if k) and
                    all(self._is_safe_literal(v) for v in node.values))
        return False

    def _is_tainted(self, node: ast.expr) -> bool:
        """Check if an expression uses tainted (user-controlled) variables."""
        if isinstance(node, ast.Name):
            return node.id in self.tainted_vars
        if isinstance(node, ast.BinOp):
            return self._is_tainted(node.left) or self._is_tainted(node.right)
        if isinstance(node, ast.JoinedStr):  # f-string
            return any(
                self._is_tainted(v.value) if isinstance(v, ast.FormattedValue) else False
                for v in node.values
            )
        if isinstance(node, ast.Call):
            return any(self._is_tainted(a) for a in node.args)
        if isinstance(node, ast.Subscript):
            return self._is_tainted(node.value)
        if isinstance(node, ast.Attribute):
            return self._is_tainted(node.value)
        return False

    def _is_formatted_string(self, node: ast.expr) -> bool:
        """Check if an expression is a formatted string (f-string, %, .format)."""
        if isinstance(node, ast.JoinedStr):
            return True
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
            return True
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute) and node.func.attr == "format":
                return True
        return False

    def _has_safe_loader(self, node: ast.Call) -> bool:
        """Check if yaml.load has a safe Loader argument."""
        for kw in node.keywords:
            if kw.arg == "Loader":
                if isinstance(kw.value, ast.Attribute):
                    return "Safe" in kw.value.attr
                if isinstance(kw.value, ast.Name):
                    return "Safe" in kw.value.id
        return False


def analyze_file(filepath: str) -> list[dict]:
    """Analyze a Python file using AST and return findings."""
    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            source = f.read()
    except Exception as e:
        return [{"error": str(e)}]

    try:
        tree = ast.parse(source, filename=filepath)
    except SyntaxError:
        # Not valid Python — skip silently
        return []

    visitor = SecurityVisitor(os.path.basename(filepath))
    visitor.visit(tree)
    return visitor.findings


def analyze_source(source: str, filename: str = "<input>") -> list[dict]:
    """Analyze Python source code string using AST."""
    try:
        tree = ast.parse(source, filename=filename)
    except SyntaxError:
        return []

    visitor = SecurityVisitor(filename)
    visitor.visit(tree)
    return visitor.findings


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 ast_analyzer.py <file_path> [file_path ...]",
              file=sys.stderr)
        sys.exit(1)

    all_findings = []
    for path in sys.argv[1:]:
        if os.path.isfile(path):
            all_findings.extend(analyze_file(path))
        elif os.path.isdir(path):
            for root, _, files in os.walk(path):
                for f in files:
                    if f.endswith(".py"):
                        all_findings.extend(analyze_file(os.path.join(root, f)))

    print(json.dumps(all_findings, indent=2))
