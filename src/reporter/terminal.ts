import chalk from "chalk";
import type { ScanResult, Finding, ScoreResult } from "../types.js";
import { riskLabel } from "../score.js";
import { getRuleReference, groupByOwasp, type RuleReference } from "../references.js";

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

export interface ReportOptions {
  /** Show numeric score and dimension breakdown (default: false) */
  showScore?: boolean;
  /** Show possible false positives (default: false) */
  showFp?: boolean;
}

/**
 * Print a risk-inventory report (default mode).
 * Groups findings by OWASP/risk category with standard references.
 * Score is only shown when opts.showScore is true.
 */
export function printReport(result: ScanResult, opts: ReportOptions = {}): void {
  const { target, filesScanned, linesScanned, findings, score, scoreResult, duration } = result;

  const divider = chalk.dim("─".repeat(60));
  const realFindings = findings.filter(f => !f.possibleFalsePositive);

  console.log();
  console.log(divider);
  console.log(chalk.bold("🛡️  AgentShield Risk Report"));
  console.log(divider);
  console.log(chalk.dim(`📁 Target:  ${target}`));
  console.log(chalk.dim(`📄 Files:   ${filesScanned} files, ${formatLines(linesScanned)}`));
  console.log(chalk.dim(`⏱  Time:    ${duration}ms`));
  console.log(divider);
  console.log();

  if (realFindings.length === 0) {
    console.log(chalk.green.bold("✅ No security risks detected."));
    if (opts.showScore) {
      const displayScore = scoreResult ? scoreResult.overall : score;
      console.log(chalk.dim(`  Reference score: ${displayScore}/100`));
    }
    console.log();
    console.log(divider);
    console.log();
    return;
  }

  // ─── Risk Summary (grouped by OWASP category) ───
  const owaspGroups = groupByOwasp(realFindings);
  const high = realFindings.filter(f => f.severity === "high").length;
  const medium = realFindings.filter(f => f.severity === "medium").length;
  const low = realFindings.filter(f => f.severity === "low").length;

  console.log(chalk.bold("📊 Risk Summary"));
  console.log();

  // Sort groups: categories with high-severity findings first
  const sortedGroups = [...owaspGroups.entries()].sort((a, b) => {
    const aMax = severityRank(a[1]);
    const bMax = severityRank(b[1]);
    return aMax - bMax;
  });

  for (const [category, groupFindings] of sortedGroups) {
    const gHigh = groupFindings.filter(f => f.severity === "high").length;
    const gMed = groupFindings.filter(f => f.severity === "medium").length;
    const gLow = groupFindings.filter(f => f.severity === "low").length;

    const ref = getRuleReference(groupFindings[0]!.rule);
    const icon = gHigh > 0 ? "🔴" : gMed > 0 ? "🟡" : "🟢";
    const counts: string[] = [];
    if (gHigh > 0) counts.push(chalk.red(`${gHigh} high`));
    if (gMed > 0) counts.push(chalk.yellow(`${gMed} medium`));
    if (gLow > 0) counts.push(chalk.green(`${gLow} low`));

    console.log(`  ${icon} ${chalk.bold(category)} (${counts.join(", ")})`);
    if (ref.owasp) {
      console.log(chalk.dim(`     ${ref.owasp.url}`));
    }
  }
  console.log();

  // ─── Detailed Findings (grouped by risk category) ───
  console.log(chalk.bold("📋 Detailed Findings"));
  console.log();

  for (const [category, groupFindings] of sortedGroups) {
    const ref = getRuleReference(groupFindings[0]!.rule);
    const headerColor = groupFindings.some(f => f.severity === "high")
      ? chalk.red : groupFindings.some(f => f.severity === "medium")
      ? chalk.yellow : chalk.green;

    // Category header with standard references
    console.log(headerColor.bold(`  [${category}]`));
    console.log(chalk.dim(`  ${ref.riskDescription}`));

    // Show references
    const refs: string[] = [];
    if (ref.owasp) refs.push(`OWASP ${ref.owasp.id}`);
    if (ref.cwe) refs.push(ref.cwe.id);
    if (ref.atlas) refs.push(`ATLAS ${ref.atlas.id}`);
    if (refs.length > 0) {
      console.log(chalk.dim(`  Standards: ${refs.join(" · ")}`));
    }

    // Show papers for high/medium findings
    if (ref.papers && groupFindings.some(f => f.severity !== "low")) {
      for (const paper of ref.papers.slice(0, 2)) {
        console.log(chalk.dim(`  Research: ${paper.authors} (${paper.year}) "${paper.title}"`));
      }
    }
    console.log();

    // Individual findings
    for (let i = 0; i < groupFindings.length; i++) {
      const f = groupFindings[i] as Finding;
      const prefix = i < groupFindings.length - 1 ? "    ├─" : "    └─";
      const loc = f.line ? `${f.file}:${f.line}` : f.file;
      const colorize = SEVERITY_LINE[f.severity] || chalk.white;
      const confLabel = f.confidence === "low" ? " [needs review]" : f.confidence === "medium" ? " [medium confidence]" : "";
      console.log(colorize(`${prefix} ${loc} — ${f.message}${confLabel}`));
      if (f.evidence) {
        const ePrefix = i < groupFindings.length - 1 ? "    │  " : "       ";
        console.log(chalk.dim(`${ePrefix}${f.evidence}`));
      }
    }
    console.log();
  }

  // ─── FP section ───
  const fpFindings = findings.filter(f => f.possibleFalsePositive);
  if (fpFindings.length > 0) {
    console.log(chalk.dim(`ℹ️  ${fpFindings.length} possible false positive${fpFindings.length > 1 ? "s" : ""} suppressed (use --show-fp to display)`));
    console.log();
  }

  // ─── Score section (optional) ───
  if (opts.showScore && scoreResult) {
    printScoreSection(scoreResult, realFindings);
  }

  console.log(divider);
  console.log();
}

/**
 * Print the optional score section.
 */
function printScoreSection(scoreResult: ScoreResult, findings: Finding[]): void {
  console.log(chalk.bold("📊 Reference Score") + chalk.dim(" (opinionated — use --score to show)"));
  console.log(chalk.dim("  This score is a density-based risk metric, not a definitive safety judgment."));
  console.log();

  const displayScore = scoreResult.overall;
  const scoreColor = displayScore >= 90 ? chalk.green : displayScore >= 75 ? chalk.yellow : displayScore >= 50 ? chalk.hex("#FF8800") : chalk.red;
  const scoreBar = generateScoreBar(displayScore);
  console.log(`  ${scoreColor.bold(`${displayScore}/100`)}  ${scoreBar}`);
  console.log();

  // Dimension breakdown
  const dims = [
    { key: "codeExec" as const, label: "Code Execution" },
    { key: "dataSafety" as const, label: "Data Safety" },
    { key: "supplyChain" as const, label: "Supply Chain" },
    { key: "promptInjection" as const, label: "Prompt Injection" },
    { key: "codeQuality" as const, label: "Code Quality" },
  ];
  for (const d of dims) {
    const dim = scoreResult.dimensions[d.key];
    const dimColor = dim.score >= 90 ? chalk.green : dim.score >= 75 ? chalk.yellow : dim.score >= 60 ? chalk.hex("#FF8800") : chalk.red;
    const bar = generateScoreBar(dim.score);
    console.log(`    ${d.label.padEnd(18)} ${dimColor.bold(String(dim.score).padStart(3))}/100 ${bar}`);
  }
  console.log();
}

function severityRank(findings: Finding[]): number {
  if (findings.some(f => f.severity === "high")) return 0;
  if (findings.some(f => f.severity === "medium")) return 1;
  return 2;
}

function formatLines(n: number): string {
  if (n >= 1000) return `${(n / 1000).toFixed(1)}K lines`;
  return `${n} lines`;
}

function generateScoreBar(score: number): string {
  const width = 20;
  const normalized = Math.max(0, Math.min(100, score));
  const filled = Math.round((normalized / 100) * width);
  const empty = width - filled;
  const color = score >= 90 ? chalk.green : score >= 75 ? chalk.yellow : score >= 50 ? chalk.hex("#FF8800") : chalk.red;
  return color("█".repeat(filled)) + chalk.dim("░".repeat(empty));
}
