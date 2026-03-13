import type { Finding, ScoreResult, DimensionScore, ProjectMeta, Grade } from "./types.js";

/**
 * AgentShield Scoring System v2
 *
 * Base score: 100 (per dimension and overall)
 * Score range: -100 to 100
 *
 * Key improvements over v1:
 *   1. Per-rule weight multipliers (reverse-shell ≠ eval)
 *   2. Diminishing returns: Nth same-rule finding decays by 0.7^(N-1)
 *   3. No floor at 0 — negative scores show extreme danger
 *   4. Five dimensions: Code Exec, Data Safety, Supply Chain, Prompt Injection, Code Quality
 *   5. Letter grades: A/B/C/D/F/F-
 */

// ─── Per-rule weight multipliers ───

const RULE_WEIGHTS: Record<string, number> = {
  // High severity — base -15
  "reverse-shell": 3.0,
  "attack-chain": 2.5,
  "cross-file": 2.0,
  "toxic-flow": 2.0,
  "crypto-mining": 2.0,
  "data-exfil": 2.0,
  backdoor: 1.8,
  "mcp-runtime": 1.8,
  privilege: 1.5,
  obfuscation: 1.3,

  // Medium severity — base -6
  "network-ssrf": 1.5,
  "python-security": 1.5,
  "go-rust-security": 1.3,
  "tool-shadowing": 1.3,
  "prompt-injection": 1.2,
  "prompt-injection-llm": 1.2,
  "multilang-injection": 1.2,
  "description-integrity": 1.2,
  "supply-chain": 1.2,
  typosquatting: 1.2,
  "phone-home": 1.0,
  "mcp-manifest": 1.0,
  "skill-risks": 1.0,

  // Low severity — base -2
  "credential-hardcode": 1.0,
  "excessive-perms": 1.0,
  "env-leak": 1.0,
  "sensitive-read": 1.0,
  "hidden-files": 0.5,
};

// ─── Severity base penalties ───

const SEVERITY_BASE: Record<string, number> = {
  high: 15,
  medium: 6,
  low: 2,
};

// ─── Dimension mapping: which rules affect which dimension ───

const DIMENSION_RULES: Record<string, Set<string>> = {
  codeExec: new Set([
    "reverse-shell", "backdoor", "attack-chain", "cross-file",
    "toxic-flow", "crypto-mining", "privilege", "obfuscation",
    "python-security", "go-rust-security", "mcp-runtime",
  ]),
  dataSafety: new Set([
    "data-exfil", "env-leak", "sensitive-read", "credential-hardcode",
    "phone-home", "network-ssrf",
  ]),
  supplyChain: new Set([
    "supply-chain", "typosquatting", "hidden-files",
  ]),
  promptInjection: new Set([
    "prompt-injection", "prompt-injection-llm", "multilang-injection",
    "tool-shadowing", "description-integrity", "skill-risks",
  ]),
  codeQuality: new Set([
    "excessive-perms", "mcp-manifest",
  ]),
};

const DIMENSION_LABELS: Record<string, string> = {
  codeExec: "Code Execution",
  dataSafety: "Data Safety",
  supplyChain: "Supply Chain",
  promptInjection: "Prompt Injection",
  codeQuality: "Code Quality",
};

// ─── Dimension weights for overall score ───

const DIMENSION_WEIGHTS: Record<string, number> = {
  codeExec: 0.35,
  dataSafety: 0.25,
  supplyChain: 0.15,
  promptInjection: 0.15,
  codeQuality: 0.10,
};

/** Diminishing returns decay factor */
const DECAY_FACTOR = 0.7;

// ─── Core scoring functions ───

/**
 * Calculate penalty for a list of findings with diminishing returns.
 * Returns total deduction and per-rule breakdown.
 */
function calcDeductions(findings: Finding[]): {
  total: number;
  byRule: Record<string, { amount: number; count: number }>;
} {
  const ruleCounts: Record<string, number> = {};
  const byRule: Record<string, { amount: number; count: number }> = {};
  let total = 0;

  for (const f of findings) {
    if (f.possibleFalsePositive) continue;

    const base = SEVERITY_BASE[f.severity] ?? 6;
    const weight = RULE_WEIGHTS[f.rule] ?? 1.0;
    const count = ruleCounts[f.rule] ?? 0;
    ruleCounts[f.rule] = count + 1;

    const penalty = base * weight * Math.pow(DECAY_FACTOR, count);
    total += penalty;

    if (!byRule[f.rule]) {
      byRule[f.rule] = { amount: 0, count: 0 };
    }
    byRule[f.rule]!.amount += penalty;
    byRule[f.rule]!.count += 1;
  }

  return { total, byRule };
}

/**
 * Compute a single dimension's score.
 */
function scoreDimension(
  name: string,
  ruleSet: Set<string>,
  findings: Finding[],
): DimensionScore {
  const relevant = findings.filter((f) => ruleSet.has(f.rule));
  const { total, byRule } = calcDeductions(relevant);

  const deductions = Object.entries(byRule).map(([rule, d]) => ({
    rule,
    amount: Math.round(d.amount * 10) / 10,
    count: d.count,
  }));

  // Dimension score: 100 - deductions, floor -100
  const score = Math.max(-100, Math.round((100 - total) * 10) / 10);

  return {
    name: DIMENSION_LABELS[name] ?? name,
    score,
    deductions,
  };
}

/**
 * Compute bonus points for good security practices.
 */
function computeBonus(meta?: ProjectMeta): { bonus: number; reasons: string[] } {
  let bonus = 0;
  const reasons: string[] = [];
  if (!meta) return { bonus: 0, reasons: [] };

  // Bonus: has security config file
  const hasSecConfig = meta.fileList.some(
    (f) => f.includes(".agent-shield") || f.includes("agent-shield.yml"),
  );
  if (hasSecConfig) {
    bonus += 3;
    reasons.push("Security config present");
  }

  // Bonus: has SECURITY.md
  const hasSecurityMd = meta.fileList.some(
    (f) => f.toLowerCase().includes("security.md"),
  );
  if (hasSecurityMd) {
    bonus += 3;
    reasons.push("SECURITY.md present");
  }

  // Bonus: has LICENSE
  const hasLicense = meta.fileList.some(
    (f) => f.toLowerCase().includes("license"),
  );
  if (hasLicense) {
    bonus += 2;
    reasons.push("LICENSE present");
  }

  // Bonus: uses TypeScript
  const hasTs = meta.fileList.some(
    (f) => f.endsWith(".ts") && !f.endsWith(".d.ts"),
  );
  if (hasTs) {
    bonus += 2;
    reasons.push("TypeScript (type safety)");
  }

  // Bonus: no network calls in a tool/plugin
  if (!meta.hasNetworkCalls && meta.totalFiles > 0) {
    bonus += 3;
    reasons.push("No network calls detected");
  }

  // Bonus: small codebase (less attack surface)
  if (meta.totalLines < 500 && meta.totalFiles <= 10) {
    bonus += 2;
    reasons.push("Small codebase");
  }

  if (meta.totalFiles < 10 && meta.totalFiles > 0) {
    bonus += 1;
    reasons.push("Simple structure");
  }

  return { bonus: Math.min(bonus, 10), reasons };
}

/**
 * Letter grade from score.
 */
export function letterGrade(score: number): Grade {
  if (score >= 90) return "A";
  if (score >= 75) return "B";
  if (score >= 60) return "C";
  if (score >= 40) return "D";
  return "F";
}

/**
 * Human-readable grade label.
 */
export function gradeLabel(score: number): string {
  if (score >= 90) return "Safe";
  if (score >= 75) return "Caution";
  if (score >= 60) return "Warning";
  if (score >= 40) return "Danger";
  return "Critical";
}

/** Human-readable risk label (alias for gradeLabel, backward compat) */
export function riskLabel(score: number): string {
  return gradeLabel(score);
}

/** Emoji for grade */
export function gradeEmoji(score: number): string {
  if (score >= 90) return "✅";
  if (score >= 75) return "🟡";
  if (score >= 60) return "🟠";
  if (score >= 40) return "🔴";
  return "⛔";
}

// ─── Public API ───

/**
 * Compute overall score (simple, backward compatible).
 * Now uses v2 logic: per-rule weights + diminishing returns + no floor at 0.
 */
export function computeScore(findings: Finding[]): number {
  const { total } = calcDeductions(findings);
  return Math.max(-100, Math.round((100 - total) * 10) / 10);
}

/**
 * Compute full v2 score with dimensions, grades, and bonus.
 */
export function computeScoreV2(findings: Finding[], meta?: ProjectMeta): ScoreResult {
  // Score each dimension
  const dimensions = {
    codeExec: scoreDimension("codeExec", DIMENSION_RULES.codeExec!, findings),
    dataSafety: scoreDimension("dataSafety", DIMENSION_RULES.dataSafety!, findings),
    supplyChain: scoreDimension("supplyChain", DIMENSION_RULES.supplyChain!, findings),
    promptInjection: scoreDimension("promptInjection", DIMENSION_RULES.promptInjection!, findings),
    codeQuality: scoreDimension("codeQuality", DIMENSION_RULES.codeQuality!, findings),
  };

  // Weighted overall = sum(dimension_score × weight)
  const weightedScore =
    dimensions.codeExec.score * DIMENSION_WEIGHTS.codeExec! +
    dimensions.dataSafety.score * DIMENSION_WEIGHTS.dataSafety! +
    dimensions.supplyChain.score * DIMENSION_WEIGHTS.supplyChain! +
    dimensions.promptInjection.score * DIMENSION_WEIGHTS.promptInjection! +
    dimensions.codeQuality.score * DIMENSION_WEIGHTS.codeQuality!;

  // Bonus — only applies when there are no high/medium findings
  const { bonus: rawBonus, reasons } = computeBonus(meta);
  const hasSecurityFindings = findings.some(f => f.severity === "high" || f.severity === "medium");
  const bonus = hasSecurityFindings ? 0 : rawBonus;

  // Overall: weighted + bonus, clamped to [-100, 100]
  const overall = Math.max(-100, Math.min(100, Math.round((weightedScore + bonus) * 10) / 10));

    const grade = letterGrade(overall);

  return {
    overall,
    grade,
    gradeLabel: `${grade} · ${gradeLabel(overall)}`,
    dimensions,
    bonus,
    bonusReasons: reasons,
  };
}

/** Get the weight for a rule (exported for docs/transparency) */
export function getRuleWeight(rule: string): number {
  return RULE_WEIGHTS[rule] ?? 1.0;
}

/** Export weights map for documentation */
export const WEIGHTS = RULE_WEIGHTS;
