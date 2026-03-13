import { collectFiles, totalLines } from "./files.js";
import { rules } from "../rules/index.js";
import { computeScore } from "../score.js";
import { loadConfig, loadIgnorePatterns, isIgnored } from "../config.js";
import type { ScanResult, Finding, ScanConfig, ScannedFile } from "../types.js";
import type { LlmProvider } from "../llm/types.js";

/** Context types where findings are likely false positives */
const FP_CONTEXTS: Record<string, string> = {
  test: "Test file — assertions and mocks commonly trigger security patterns",
  deploy: "Deploy/CI script — HTTP requests and credential access are expected",
};

/** Rules most likely to false-positive in specific contexts */
const CONTEXT_FP_RULES: Record<string, Set<string>> = {
  test: new Set(["data-exfil", "env-leak", "backdoor", "network-ssrf", "sensitive-read", "phone-home"]),
  deploy: new Set(["data-exfil", "env-leak", "backdoor", "network-ssrf", "credential-hardcode"]),
};

/** Run all rules against a target directory */
export function scan(targetDir: string, configOverride?: Partial<ScanConfig>): ScanResult {
  const start = Date.now();

  // Load config
  const fileConfig = loadConfig(targetDir);
  const config: ScanConfig = { ...fileConfig, ...configOverride };

  // Load ignore patterns
  const ignorePatterns = loadIgnorePatterns(targetDir);
  if (config.ignore) {
    ignorePatterns.push(...config.ignore);
  }

  // Collect and filter files
  let files = collectFiles(targetDir);
  if (ignorePatterns.length > 0) {
    files = files.filter((f) => !isIgnored(f.relativePath, ignorePatterns));
  }

  // Filter rules based on config
  let activeRules = [...rules];
  if (config.rules?.enable) {
    activeRules = activeRules.filter((r) => config.rules!.enable!.includes(r.id));
  }
  if (config.rules?.disable) {
    activeRules = activeRules.filter((r) => !config.rules!.disable!.includes(r.id));
  }

  // Run rules
  const findings: Finding[] = [];
  for (const rule of activeRules) {
    findings.push(...rule.run(files));
  }

  // Post-process: false positive detection, severity overrides, sorting
  postProcess(findings, files, config);

  return {
    target: targetDir,
    filesScanned: files.length,
    linesScanned: totalLines(files),
    findings,
    score: computeScore(findings),
    duration: Date.now() - start,
  };
}

/** Common post-processing: false positive detection, severity overrides, sorting */
function postProcess(findings: Finding[], files: ScannedFile[], config: ScanConfig): void {
  for (const finding of findings) {
    const file = files.find(
      (f) => f.relativePath === finding.file || f.path === finding.file
    );
    if (file && FP_CONTEXTS[file.context]) {
      const fpRules = CONTEXT_FP_RULES[file.context];
      if (fpRules?.has(finding.rule)) {
        finding.possibleFalsePositive = true;
        finding.falsePositiveReason = FP_CONTEXTS[file.context]!;
        if (finding.severity === "critical") {
          finding.severity = "warning";
        } else if (finding.severity === "warning") {
          finding.severity = "info";
        }
      }
    }
  }
  if (config.severity) {
    for (const finding of findings) {
      if (config.severity[finding.rule]) {
        finding.severity = config.severity[finding.rule]!;
      }
    }
  }
  const severityOrder = { critical: 0, warning: 1, info: 2 };
  findings.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);
}

/** LLM-capable file extensions for deep analysis */
const LLM_SCAN_EXTS = new Set([".md", ".json", ".yaml", ".yml", ".py"]);

/** Run all rules + optional LLM deep analysis */
export async function scanWithLlm(
  targetDir: string,
  llmProvider: LlmProvider,
  configOverride?: Partial<ScanConfig>,
): Promise<ScanResult> {
  const start = Date.now();

  const fileConfig = loadConfig(targetDir);
  const config: ScanConfig = { ...fileConfig, ...configOverride };
  const ignorePatterns = loadIgnorePatterns(targetDir);
  if (config.ignore) ignorePatterns.push(...config.ignore);

  let files = collectFiles(targetDir);
  if (ignorePatterns.length > 0) {
    files = files.filter((f) => !isIgnored(f.relativePath, ignorePatterns));
  }

  let activeRules = [...rules];
  if (config.rules?.enable) {
    activeRules = activeRules.filter((r) => config.rules!.enable!.includes(r.id));
  }
  if (config.rules?.disable) {
    activeRules = activeRules.filter((r) => !config.rules!.disable!.includes(r.id));
  }

  // Phase 1: static regex rules
  const findings: Finding[] = [];
  for (const rule of activeRules) {
    findings.push(...rule.run(files));
  }

  // Phase 2: LLM deep analysis on markdown, config, and Python files
  const llmTargets = files.filter((f) => LLM_SCAN_EXTS.has(f.ext));
  let totalTokens = 0;

  for (const file of llmTargets) {
    try {
      const result = await llmProvider.analyze(file.content, file.relativePath);
      totalTokens += result.tokensUsed || 0;

      for (const llmFinding of result.findings) {
        // Deduplicate: skip if regex already found a similar issue on the same line
        const isDuplicate = findings.some(
          (f) =>
            f.file === file.relativePath &&
            f.line === llmFinding.line &&
            f.rule === "prompt-injection",
        );
        if (!isDuplicate) {
          findings.push({
            rule: "prompt-injection-llm",
            severity: llmFinding.severity,
            file: file.relativePath,
            line: llmFinding.line,
            message: `[LLM] ${llmFinding.description}`,
            evidence: llmFinding.evidence,
          });
        }
      }
    } catch (err) {
      // LLM failure is non-fatal — fallback to regex-only
      findings.push({
        rule: "prompt-injection-llm",
        severity: "info",
        file: file.relativePath,
        message: `LLM analysis skipped: ${(err as Error).message?.slice(0, 80) || "unknown error"}`,
      });
    }
  }

  postProcess(findings, files, config);

  return {
    target: targetDir,
    filesScanned: files.length,
    linesScanned: totalLines(files),
    findings,
    score: computeScore(findings),
    duration: Date.now() - start,
  };
}
