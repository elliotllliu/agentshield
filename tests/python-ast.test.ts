import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { pythonAstRule } from "../src/rules/python-ast.js";
import type { ScannedFile } from "../src/types.js";

function pyFile(name: string, content: string): ScannedFile {
  return {
    path: `/fake/${name}`,
    relativePath: name,
    content,
    lines: content.split("\n"),
    ext: ".py",
    context: "source",
  };
}

describe("python-ast: taint tracking", () => {
  it("flags eval with tainted input as HIGH", () => {
    const f = pyFile("vuln.py", `
user = input("cmd: ")
result = eval(user)
`);
    const findings = pythonAstRule.run([f]);
    assert.ok(findings.some(f => f.message.includes("tainted") && f.severity === "high"));
  });

  it("does NOT flag eval with safe literal", () => {
    const f = pyFile("safe.py", `
result = eval("{'a': 1, 'b': 2}")
`);
    const findings = pythonAstRule.run([f]);
    assert.equal(findings.filter(f => f.rule.startsWith("ast-")).length, 0);
  });

  it("flags subprocess with tainted input", () => {
    const f = pyFile("cmd.py", `
import subprocess
cmd = input("run: ")
subprocess.run(cmd, shell=True)
`);
    const findings = pythonAstRule.run([f]);
    assert.ok(findings.some(f => f.message.includes("command injection") && f.severity === "high"));
  });
});

describe("python-ast: SQL injection", () => {
  it("flags f-string SQL", () => {
    const f = pyFile("sql.py", `
user_id = input("id: ")
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
`);
    const findings = pythonAstRule.run([f]);
    assert.ok(findings.some(f => f.message.includes("SQL injection")));
  });
});

describe("python-ast: deserialization", () => {
  it("flags pickle.loads", () => {
    const f = pyFile("deser.py", `
import pickle
data = pickle.loads(raw_data)
`);
    const findings = pythonAstRule.run([f]);
    assert.ok(findings.some(f => f.message.includes("deserialization")));
  });

  it("flags yaml.load without SafeLoader", () => {
    const f = pyFile("yaml_vuln.py", `
import yaml
config = yaml.load(data)
`);
    const findings = pythonAstRule.run([f]);
    assert.ok(findings.some(f => f.message.includes("deserialization")));
  });

  it("does NOT flag yaml.safe_load", () => {
    const f = pyFile("yaml_safe.py", `
import yaml
config = yaml.safe_load(data)
`);
    const findings = pythonAstRule.run([f]);
    assert.equal(findings.filter(f => f.message.includes("deserialization")).length, 0);
  });
});

describe("python-ast: clean code", () => {
  it("does NOT flag normal Python code", () => {
    const f = pyFile("normal.py", `
import os
import json

def process(data):
    result = json.loads(data)
    return {"status": "ok", "data": result}
`);
    const findings = pythonAstRule.run([f]);
    assert.equal(findings.length, 0);
  });
});
