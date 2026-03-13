#!/usr/bin/env node
/**
 * AgentShield Detection Benchmark Runner
 *
 * Evaluates detection accuracy across malicious and benign samples.
 * Computes recall, false positive rate, precision, and F1 score.
 */

import { scan } from "../src/scanner/index.js";
import { readdirSync, writeFileSync } from "fs";
import { join } from "path";

const BENCHMARK_DIR = join(import.meta.dirname || __dirname, ".");
const MALICIOUS_DIR = join(BENCHMARK_DIR, "malicious");
const BENIGN_DIR = join(BENCHMARK_DIR, "benign");

interface BenchmarkResult {
  file: string;
  expectedMalicious: boolean;
  criticalFindings: number;
  warningFindings: number;
  totalFindings: number;
  score: number;
  detected: boolean; // true if any critical/warning found (for malicious) or false (for benign)
  rules: string[];
}

function runBenchmark() {
  const results: BenchmarkResult[] = [];
  const startTime = Date.now();

  // Scan malicious directory as a whole
  console.log("🔴 Scanning malicious samples...\n");
  const maliciousResult = scan(MALICIOUS_DIR);
  const maliciousFiles = readdirSync(MALICIOUS_DIR).filter(f => f.endsWith(".md") || f.endsWith(".json") || f.endsWith(".py") || f.endsWith(".sh") || f.endsWith(".ts") || f.endsWith(".js"));

  for (const file of maliciousFiles) {
    const fileFindings = maliciousResult.findings.filter(f => f.file.includes(file));
    const criticals = fileFindings.filter(f => f.severity === "critical" && !f.possibleFalsePositive);
    const warnings = fileFindings.filter(f => f.severity === "warning" && !f.possibleFalsePositive);
    const detected = criticals.length > 0 || warnings.length > 0;
    const rules = [...new Set(fileFindings.map(f => f.rule))];

    results.push({
      file: `malicious/${file}`,
      expectedMalicious: true,
      criticalFindings: criticals.length,
      warningFindings: warnings.length,
      totalFindings: fileFindings.length,
      score: detected ? 0 : 100,
      detected,
      rules,
    });

    const status = detected ? "✅ DETECTED" : "❌ MISSED";
    console.log(`  ${status} ${file} — ${criticals.length}C/${warnings.length}W`);
  }

  // Scan benign directory as a whole
  console.log("\n🟢 Scanning benign samples...\n");
  const benignResult = scan(BENIGN_DIR);
  const benignFiles = readdirSync(BENIGN_DIR).filter(f => f.endsWith(".md") || f.endsWith(".json") || f.endsWith(".py") || f.endsWith(".sh") || f.endsWith(".ts") || f.endsWith(".js"));

  for (const file of benignFiles) {
    const fileFindings = benignResult.findings.filter(f => f.file.includes(file));
    const criticals = fileFindings.filter(f => f.severity === "critical" && !f.possibleFalsePositive);
    const warnings = fileFindings.filter(f => f.severity === "warning" && !f.possibleFalsePositive);
    const falsePositive = criticals.length > 0;
    const rules = [...new Set(fileFindings.map(f => f.rule))];

    results.push({
      file: `benign/${file}`,
      expectedMalicious: false,
      criticalFindings: criticals.length,
      warningFindings: warnings.length,
      totalFindings: fileFindings.length,
      score: benignResult.score,
      detected: falsePositive,
      rules,
    });

    const status = falsePositive ? "❌ FALSE POSITIVE" : "✅ CLEAN";
    console.log(`  ${status} ${file} — ${criticals.length}C/${warnings.length}W`);
  }

  // Calculate metrics
  const malicious = results.filter(r => r.expectedMalicious);
  const benign = results.filter(r => !r.expectedMalicious);

  const truePositives = malicious.filter(r => r.detected).length;
  const falseNegatives = malicious.filter(r => !r.detected).length;
  const falsePositives = benign.filter(r => r.detected).length;
  const trueNegatives = benign.filter(r => !r.detected).length;

  const recall = truePositives / (truePositives + falseNegatives) || 0;
  const fpr = falsePositives / (falsePositives + trueNegatives) || 0;
  const precision = truePositives / (truePositives + falsePositives) || 0;
  const f1 = 2 * precision * recall / (precision + recall) || 0;
  const accuracy = (truePositives + trueNegatives) / results.length;

  const duration = Date.now() - startTime;

  console.log("\n" + "=".repeat(60));
  console.log("📊 BENCHMARK RESULTS");
  console.log("=".repeat(60));
  console.log(`\nSamples: ${malicious.length} malicious + ${benign.length} benign = ${results.length} total`);
  console.log(`Duration: ${duration}ms\n`);
  console.log(`  True Positives:  ${truePositives}/${malicious.length}`);
  console.log(`  False Negatives: ${falseNegatives}/${malicious.length}`);
  console.log(`  True Negatives:  ${trueNegatives}/${benign.length}`);
  console.log(`  False Positives: ${falsePositives}/${benign.length}`);
  console.log();
  console.log(`  Recall:    ${(recall * 100).toFixed(1)}%`);
  console.log(`  Precision: ${(precision * 100).toFixed(1)}%`);
  console.log(`  F1 Score:  ${(f1 * 100).toFixed(1)}%`);
  console.log(`  FPR:       ${(fpr * 100).toFixed(1)}%`);
  console.log(`  Accuracy:  ${(accuracy * 100).toFixed(1)}%`);

  // Write results to file
  const report = `# AgentShield Benchmark Results

Generated: ${new Date().toISOString()}
Duration: ${duration}ms

## Summary

| Metric | Value |
|--------|-------|
| Malicious samples | ${malicious.length} |
| Benign samples | ${benign.length} |
| True Positives | ${truePositives}/${malicious.length} |
| False Negatives | ${falseNegatives} |
| True Negatives | ${trueNegatives}/${benign.length} |
| False Positives | ${falsePositives} |
| **Recall** | **${(recall * 100).toFixed(1)}%** |
| **Precision** | **${(precision * 100).toFixed(1)}%** |
| **F1 Score** | **${(f1 * 100).toFixed(1)}%** |
| **FPR** | **${(fpr * 100).toFixed(1)}%** |
| **Accuracy** | **${(accuracy * 100).toFixed(1)}%** |

## Malicious Samples

| File | Detected | Critical | Warning | Score | Rules |
|------|----------|----------|---------|-------|-------|
${malicious.map(r => `| ${r.file} | ${r.detected ? "✅" : "❌"} | ${r.criticalFindings} | ${r.warningFindings} | ${r.score} | ${r.rules.join(", ")} |`).join("\n")}

## Benign Samples

| File | Clean | Critical | Warning | Score |
|------|-------|----------|---------|-------|
${benign.map(r => `| ${r.file} | ${!r.detected ? "✅" : "❌"} | ${r.criticalFindings} | ${r.warningFindings} | ${r.score} |`).join("\n")}
`;

  writeFileSync(join(BENCHMARK_DIR, "results.md"), report);
  console.log(`\n📄 Results saved to benchmark/results.md`);
}

runBenchmark();
