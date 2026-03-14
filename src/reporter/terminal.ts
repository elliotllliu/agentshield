import chalk from "chalk";
import type { ScanResult, Finding, ScoreResult } from "../types.js";
import { riskLabel } from "../score.js";

const SEVERITY_ICON: Record<string, string> = {
  high: chalk.red("🔴 High Risk"),
  medium: chalk.yellow("🟡 Medium Risk"),
  low: chalk.green("🟢 Low Risk"),
};

const SEVERITY_LINE: Record<string, (s: string) => string> = {
  high: chalk.red,
  medium: chalk.yellow,
  low: chalk.green,
};

export function printReport(result: ScanResult): void {
  const { target, filesScanned, linesScanned, findings, score, scoreResult, duration } = result;

  const divider = chalk.dim("─".repeat(60));

  console.log();
  console.log(divider);
  console.log(chalk.bold("🛡️  AgentShield Scan Report"));
  console.log(divider);
  console.log(
    chalk.dim(`📁 Target:  ${target}`),
  );
  console.log(
    chalk.dim(`📄 Files:   ${filesScanned} files, ${formatLines(linesScanned)}`),
  );
  console.log(
    chalk.dim(`⏱  Time:    ${duration}ms`),
  );
  console.log(divider);
  console.log();

  // Summary line first
  const high = findings.filter(f => f.severity === "high" && !f.possibleFalsePositive).length;
  const medium = findings.filter(f => f.severity === "medium" && !f.possibleFalsePositive).length;
  const low = findings.filter(f => f.severity === "low" && !f.possibleFalsePositive).length;

  // Use v2 score if available
  const displayScore = scoreResult ? scoreResult.overall : score;
  const gradeInfo = scoreResult ? `${scoreResult.grade} · ${scoreResult.gradeLabel}` : riskLabel(displayScore);

  const scoreColor = displayScore >= 90 ? chalk.green : displayScore >= 75 ? chalk.yellow : displayScore >= 50 ? chalk.hex("#FF8800") : displayScore >= 0 ? chalk.red : chalk.redBright;
  const scoreBar = generateScoreBar(displayScore);
  console.log(scoreColor.bold(`Score: ${displayScore}/100`) + "  " + scoreBar + "  " + scoreColor(`(${gradeInfo})`));
  console.log();

  // Dimension breakdown (v2)
  if (scoreResult) {
    console.log(chalk.bold("📊 Dimension Scores:"));
    const dims = [
      { key: "codeExec" as const, label: "Code Execution" },
      { key: "dataSafety" as const, label: "Data Safety" },
      { key: "supplyChain" as const, label: "Supply Chain" },
      { key: "promptInjection" as const, label: "Prompt Injection" },
      { key: "codeQuality" as const, label: "Code Quality" },
    ];
    for (const d of dims) {
      const dim = scoreResult.dimensions[d.key];
      const dimColor = dim.score >= 90 ? chalk.green : dim.score >= 75 ? chalk.yellow : dim.score >= 60 ? chalk.hex("#FF8800") : dim.score >= 40 ? chalk.red : chalk.redBright;
      const bar = generateScoreBar(dim.score);
      const label = d.label.padEnd(18);
      console.log(`  ${dimColor(label)} ${dimColor.bold(String(dim.score).padStart(3))}/100 ${bar}`);
    }
    console.log();

    // Bonus
    if (scoreResult.bonus > 0) {
      console.log(chalk.bold(`🏅 Bonus: +${scoreResult.bonus}`) + chalk.dim(` (${scoreResult.bonusReasons.join(", ")})`));
      console.log();
    }

    // Score breakdown (transparency)
    if (findings.filter(f => !f.possibleFalsePositive).length > 0) {
      console.log(chalk.bold("📋 Score Breakdown:"));
      console.log(chalk.dim(`  Base: 100`));

      // Collect deductions by rule
      const deductions: Array<{ rule: string; severity: string; confidence: string; count: number; total: number }> = [];
      const ruleTotals: Record<string, { severity: string; confidence: string; count: number; total: number }> = {};

      for (const f of findings.filter(f => !f.possibleFalsePositive)) {
        const key = `${f.rule}|${f.severity}|${f.confidence || "medium"}`;
        if (!ruleTotals[key]) {
          ruleTotals[key] = { severity: f.severity, confidence: f.confidence || "medium", count: 0, total: 0 };
        }
        ruleTotals[key]!.count++;
      }

      // Calculate approximate penalty for each group
      for (const [key, info] of Object.entries(ruleTotals)) {
        const rule = key.split("|")[0]!;
        deductions.push({ rule, severity: info.severity, confidence: info.confidence, count: info.count, total: 0 });
      }

      // Sort by severity (high → medium → low)
      const sevOrder: Record<string, number> = { high: 0, medium: 1, low: 2 };
      deductions.sort((a, b) => (sevOrder[a.severity] ?? 2) - (sevOrder[b.severity] ?? 2));

      for (const d of deductions) {
        const confLabel = d.confidence === "high" ? "" : d.confidence === "low" ? ", conf: low → ×0.3" : ", conf: medium → ×0.6";
        const countLabel = d.count > 1 ? ` ×${d.count}` : "";
        const sevColor = d.severity === "high" ? chalk.red : d.severity === "medium" ? chalk.yellow : chalk.green;
        console.log(sevColor(`  ${d.rule}${countLabel} (${d.severity}${confLabel})`));
      }

      // Caps
      const hasHighFindings = findings.some(f => f.severity === "high" && !f.possibleFalsePositive);
      const hasMediumFindings = findings.some(f => f.severity === "medium" && !f.possibleFalsePositive);
      if (hasHighFindings) {
        console.log(chalk.red.dim(`  ⚠ Cap applied: high findings present → max 30`));
      } else if (hasMediumFindings) {
        console.log(chalk.yellow.dim(`  ⚠ Cap applied: medium findings present → max 85`));
      }

      if (scoreResult.bonus === 0 && (hasHighFindings || hasMediumFindings)) {
        console.log(chalk.dim(`  ⚠ Bonus suppressed (security findings present)`));
      }

      console.log(chalk.bold(`  Final: ${scoreResult.overall}/100`));
      console.log();
    }
  }

  if (high > 0) console.log(chalk.red(`🔴 High Risk: ${high} finding${high > 1 ? "s" : ""}`));
  if (medium > 0) console.log(chalk.yellow(`🟡 Medium Risk: ${medium} finding${medium > 1 ? "s" : ""}`));
  if (low > 0) console.log(chalk.green(`🟢 Low Risk: ${low} finding${low > 1 ? "s" : ""}`));
  console.log();

  // Group by severity, ordered high → medium → low
  const bySeverity = groupBy(findings.filter(f => !f.possibleFalsePositive), (f) => f.severity);

  for (const severity of ["high", "medium", "low"] as const) {
    const group = bySeverity[severity];
    if (!group || group.length === 0) continue;

    console.log(`${SEVERITY_ICON[severity]} (${group.length})`);
    for (let i = 0; i < group.length; i++) {
      const f = group[i]!;
      const prefix = i < group.length - 1 ? "  ├─" : "  └─";
      const loc = f.line ? `${f.file}:${f.line}` : f.file;
      const colorize = SEVERITY_LINE[f.severity] || chalk.white;
      const confLabel = f.confidence === "high" ? "" : f.confidence === "medium" ? " [medium confidence]" : f.confidence === "low" ? " [needs review]" : "";
      console.log(colorize(`${prefix} ${loc} — [${f.rule}] ${f.message}${confLabel}`));
      if (f.evidence) {
        const ePrefix = i < group.length - 1 ? "  │  " : "     ";
        console.log(chalk.dim(`${ePrefix}${f.evidence}`));
      }
    }
    console.log();
  }

  // FP section (collapsed)
  const fpFindings = findings.filter(f => f.possibleFalsePositive);
  if (fpFindings.length > 0) {
    console.log(chalk.dim(`ℹ️  ${fpFindings.length} possible false positive${fpFindings.length > 1 ? "s" : ""} suppressed (use --show-fp to display)`));
    console.log();
  }

  if (findings.filter(f => !f.possibleFalsePositive).length === 0) {
    console.log(chalk.green.bold("✅ No security issues found!"));
    console.log();
  }

  console.log(divider);
  console.log();
}

function formatLines(n: number): string {
  if (n >= 1000) return `${(n / 1000).toFixed(1)}K lines`;
  return `${n} lines`;
}

function generateScoreBar(score: number): string {
  const width = 20;
  // Normalize: -100..100 → 0..20
  const normalized = Math.max(0, Math.min(100, score));
  const filled = Math.round((normalized / 100) * width);
  const empty = width - filled;
  const color = score >= 90 ? chalk.green : score >= 75 ? chalk.yellow : score >= 50 ? chalk.hex("#FF8800") : score >= 0 ? chalk.red : chalk.redBright;
  return color("█".repeat(filled)) + chalk.dim("░".repeat(empty));
}

function groupBy<T>(arr: T[], fn: (item: T) => string): Record<string, T[]> {
  const result: Record<string, T[]> = {};
  for (const item of arr) {
    const key = fn(item);
    if (!result[key]) result[key] = [];
    result[key]!.push(item);
  }
  return result;
}
