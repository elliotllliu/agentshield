import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { scan } from "../src/scanner/index.js";
import { computeScore, riskLabel } from "../src/score.js";
import { collectFiles } from "../src/scanner/files.js";
import { resolve } from "path";

// ============================================================
// Integration: scan fixtures
// ============================================================
describe("integration: scan malicious-skill", () => {
  it("produces critical findings and low score", () => {
    const result = scan(resolve("tests/fixtures/malicious-skill"));
    assert.ok(result.findings.length > 0);
    assert.ok(result.findings.some((f) => f.severity === "high"));
    assert.ok(result.scoreResult.overall < 50, `score ${result.scoreResult.overall} should be < 50`);
    assert.ok(result.filesScanned >= 2);
    assert.ok(result.duration >= 0);
  });
});

describe("integration: scan safe-skill", () => {
  it("produces high score with no critical findings", () => {
    const result = scan(resolve("tests/fixtures/safe-skill"));
    assert.equal(result.findings.filter((f) => f.severity === "high").length, 0);
    // Score should be >= 85 due to new scoring logic (cap at 85 if medium findings, but no high)
    assert.ok(result.scoreResult.overall >= 85, `score ${result.scoreResult.overall} should be >= 85`);
  });
});

// ============================================================
// Edge cases
// ============================================================
describe("edge: empty directory", () => {
  it("returns zero files and high score for non-existent dir", () => {
    const result = scan(resolve("tests/fixtures/nonexistent-dir-12345"));
    assert.equal(result.filesScanned, 0);
    assert.equal(result.scoreResult.overall, 100); // No findings, so 100
  });
});

describe("edge: collectFiles skips binary extensions", () => {
  it("does not collect .png or .exe files", () => {
    // collectFiles only collects CODE_EXTS, so binary files are inherently skipped
    const files = collectFiles(resolve("tests/fixtures/safe-skill"));
    assert.ok(files.every((f) => !f.ext.match(/\.(png|exe|jpg|gif|wasm)$/)));
  });
});

// ============================================================
// Score
// ============================================================
describe("score", () => {
  it("returns 100 for no findings", () => {
    assert.equal(computeScore([]), 100);
  });

  it("applies diminishing deduction for high severity", () => {
    const findings = [
      { rule: "test", severity: "high" as const, file: "a.ts", message: "bad" },
    ];
    // No confidence set → defaults to "medium" (0.6 multiplier)
    // high penalty: 35 * 1.0 * 0.6 = 21 → score = 79
    const score = computeScore(findings);
    assert.equal(score, 79);
  });

  it("applies diminishing deduction for medium severity", () => {
    const findings = [
      { rule: "test", severity: "medium" as const, file: "a.ts", message: "meh" },
    ];
    // medium penalty: 10 * 1.0 * 0.6 = 6 → score = 94
    assert.equal(computeScore(findings), 94);
  });

  it("deducts 2 per low risk", () => {
    const findings = [
      { rule: "test", severity: "low" as const, file: "a.ts", message: "ok" },
    ];
    // low penalty: 3 * 1.0 * 0.6 = 1.8 → score = 98.2
    assert.equal(computeScore(findings), 98.2);
  });

  it("diminishing returns prevent score from reaching 0", () => {
    const findings = Array.from({ length: 10 }, () => ({
      rule: "test", severity: "high" as const, file: "a.ts", message: "bad",
    }));
    // With 10 high findings at medium confidence (0.6): still significant deduction
    const score = computeScore(findings);
    assert.ok(score >= 0, `score ${score} should be >= 0 (floor is 0)`);
    assert.ok(score <= 35, `score ${score} should be <= 35 with many high findings`);
  });

  it("riskLabel returns correct labels", () => {
    assert.equal(riskLabel(95), "Safe");
    assert.equal(riskLabel(80), "Caution");
    assert.equal(riskLabel(65), "Warning");
    assert.equal(riskLabel(50), "Danger");
    assert.equal(riskLabel(20), "Critical");
  });
});