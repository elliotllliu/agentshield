import chalk from "chalk";
import type { ScanResult, Finding, ScoreResult } from "../types.js";
import { getRuleReference, groupByOwasp } from "../references.js";

const i18n = {
  zh: {
    title: "AgentShield 风险报告",
    target: "扫描目标",
    files: "扫描文件",
    time: "耗时",
    riskSummary: "风险概览",
    detailedFindings: "详细发现",
    noRisk: "✅ 未检测到安全风险",
    fpSuppressed: "条可能的误报已隐藏（使用 --show-fp 显示）",
    refScore: "📊 参考分数",
    scoreNote: "（主观指标 — 基于风险密度计算，非权威评判）",
    confidence: { high: "", medium: " [中置信度]", low: " [需审查]" },
  },
  en: {
    title: "AgentShield Risk Report",
    target: "Target",
    files: "Files",
    time: "Time",
    riskSummary: "Risk Summary",
    detailedFindings: "Detailed Findings",
    noRisk: "✅ No security risks detected.",
    fpSuppressed: "possible false positives suppressed (use --show-fp to display)",
    refScore: "📊 Reference Score",
    scoreNote: "(opinionated — density-based risk metric, not a definitive safety judgment)",
    confidence: { high: "", medium: " [medium confidence]", low: " [needs review]" },
  },
};

export interface ReportOptions {
  showScore?: boolean;
  showFp?: boolean;
  lang?: "zh" | "en";
}

export function printReport(result: ScanResult, opts: ReportOptions = {}): void {
  const lang = opts.lang || "zh";
  const t = i18n[lang];
  const { target, filesScanned, linesScanned, findings, scoreResult, duration } = result;

  const divider = chalk.dim("─".repeat(60));
  const realFindings = findings.filter(f => !f.possibleFalsePositive);

  console.log();
  console.log(divider);
  console.log(chalk.bold(`🛡️  ${t.title}`));
  console.log(divider);
  console.log(chalk.dim(`📁 ${t.target}:  ${target}`));
  console.log(chalk.dim(`📄 ${t.files}:   ${filesScanned} files, ${formatLines(linesScanned)}`));
  console.log(chalk.dim(`⏱  ${t.time}:    ${duration}ms`));
  console.log(divider);
  console.log();

  if (realFindings.length === 0) {
    console.log(chalk.green.bold(t.noRisk));
    if (opts.showScore && scoreResult) {
      console.log(chalk.dim(`  ${t.refScore}: ${scoreResult.overall}/100`));
    }
    console.log();
    console.log(divider);
    console.log();
    return;
  }

  // Risk Summary
  const owaspGroups = groupByOwasp(realFindings);
  const high = realFindings.filter(f => f.severity === "high").length;
  const medium = realFindings.filter(f => f.severity === "medium").length;
  const low = realFindings.filter(f => f.severity === "low").length;

  console.log(chalk.bold(`📊 ${t.riskSummary}`));
  console.log();

  const sortedGroups = [...owaspGroups.entries()].sort((a, b) => sevRank(a[1]) - sevRank(b[1]));

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
    if (ref.owasp) console.log(chalk.dim(`     ${ref.owasp.url}`));
  }
  console.log();

  // Detailed Findings
  console.log(chalk.bold(`📋 ${t.detailedFindings}`));
  console.log();

  for (const [category, groupFindings] of sortedGroups) {
    const ref = getRuleReference(groupFindings[0]!.rule);
    const headerColor = groupFindings.some(f => f.severity === "high")
      ? chalk.red : groupFindings.some(f => f.severity === "medium")
      ? chalk.yellow : chalk.green;

    console.log(headerColor.bold(`  [${category}]`));
    console.log(chalk.dim(`  ${ref.riskDescription}`));

    const refs: string[] = [];
    if (ref.owasp) refs.push(`OWASP ${ref.owasp.id}`);
    if (ref.cwe) refs.push(ref.cwe.id);
    if (ref.atlas) refs.push(`ATLAS ${ref.atlas.id}`);
    if (refs.length > 0) console.log(chalk.dim(`  Standards: ${refs.join(" · ")}`));

    if (ref.papers && groupFindings.some(f => f.severity !== "low")) {
      for (const paper of ref.papers.slice(0, 2)) {
        console.log(chalk.dim(`  Research: ${paper.authors} (${paper.year}) "${paper.title}"`));
      }
    }
    console.log();

    for (let i = 0; i < groupFindings.length; i++) {
      const f = groupFindings[i]!;
      const prefix = i < groupFindings.length - 1 ? "    ├─" : "    └─";
      const loc = f.line ? `${f.file}:${f.line}` : f.file;
      const colorize = f.severity === "high" ? chalk.red : f.severity === "medium" ? chalk.yellow : chalk.green;
      const confLabel = t.confidence[f.confidence as keyof typeof t.confidence] || "";
      console.log(colorize(`${prefix} ${loc} — ${f.message}${confLabel}`));
      if (f.evidence) {
        const ePrefix = i < groupFindings.length - 1 ? "    │  " : "       ";
        console.log(chalk.dim(`${ePrefix}${f.evidence}`));
      }
    }
    console.log();
  }

  // FP section
  const fpCount = findings.length - realFindings.length;
  if (fpCount > 0) {
    console.log(chalk.dim(`ℹ️  ${fpCount} ${t.fpSuppressed}`));
    console.log();
  }

  // Score (optional)
  if (opts.showScore && scoreResult) {
    printScoreSection(scoreResult, t);
  }

  console.log(divider);
  console.log();
}

function printScoreSection(scoreResult: ScoreResult, t: typeof i18n.zh): void {
  console.log(chalk.bold(t.refScore) + chalk.dim(` ${t.scoreNote}`));
  console.log();

  const s = scoreResult.overall;
  const color = s >= 90 ? chalk.green : s >= 75 ? chalk.yellow : s >= 50 ? chalk.hex("#FF8800") : chalk.red;
  console.log(`  ${color.bold(`${s}/100`)}  ${scoreBar(s)}`);
  console.log();

  const dims = [
    { key: "codeExec" as const, label: "Code Execution" },
    { key: "dataSafety" as const, label: "Data Safety" },
    { key: "supplyChain" as const, label: "Supply Chain" },
    { key: "promptInjection" as const, label: "Prompt Injection" },
    { key: "codeQuality" as const, label: "Code Quality" },
  ];
  for (const d of dims) {
    const dim = scoreResult.dimensions[d.key];
    const c = dim.score >= 90 ? chalk.green : dim.score >= 75 ? chalk.yellow : dim.score >= 60 ? chalk.hex("#FF8800") : chalk.red;
    console.log(`    ${d.label.padEnd(18)} ${c.bold(String(dim.score).padStart(3))}/100 ${scoreBar(dim.score)}`);
  }
  console.log();
}

function sevRank(findings: Finding[]): number {
  if (findings.some(f => f.severity === "high")) return 0;
  if (findings.some(f => f.severity === "medium")) return 1;
  return 2;
}

function formatLines(n: number): string {
  return n >= 1000 ? `${(n / 1000).toFixed(1)}K lines` : `${n} lines`;
}

function scoreBar(score: number): string {
  const w = 20;
  const filled = Math.round((Math.max(0, Math.min(100, score)) / 100) * w);
  const color = score >= 90 ? chalk.green : score >= 75 ? chalk.yellow : score >= 50 ? chalk.hex("#FF8800") : chalk.red;
  return color("█".repeat(filled)) + chalk.dim("░".repeat(w - filled));
}
