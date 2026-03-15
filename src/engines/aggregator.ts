import chalk from "chalk";
import type {
  EngineAdapter, EngineResult, AggregatedResult,
  CrossValidatedFinding, EngineFinding,
} from "./types.js";
import { AgentShieldAdapter } from "./agentshield.js";
import { AguaraAdapter } from "./aguara.js";
import { TencentGuardAdapter } from "./tencent.js";
import { SkillVetterAdapter } from "./skill-vetter.js";
import { SemgrepAdapter } from "./semgrep.js";

/**
 * Registry of all available engine adapters.
 */
const ALL_ENGINES: EngineAdapter[] = [
  new AgentShieldAdapter(),
  new AguaraAdapter(),
  new SkillVetterAdapter(),
  new SemgrepAdapter(),
  new TencentGuardAdapter(),
];

/**
 * Get engine by id.
 */
export function getEngine(id: string): EngineAdapter | undefined {
  return ALL_ENGINES.find(e => e.id === id);
}

/**
 * List all registered engines.
 */
export function listEngines(): EngineAdapter[] {
  return ALL_ENGINES;
}

/**
 * Run multiple engines and aggregate results.
 */
export async function aggregateScan(
  targetDir: string,
  engineIds?: string[],
): Promise<AggregatedResult> {
  const start = Date.now();
  const engines = engineIds
    ? ALL_ENGINES.filter(e => engineIds.includes(e.id))
    : ALL_ENGINES;

  // Check availability first
  console.log(chalk.bold("\n🔍 Multi-Engine Scan\n"));
  const availability: Array<{ engine: EngineAdapter; available: boolean }> = [];
  for (const engine of engines) {
    const avail = await engine.isAvailable();
    const icon = avail ? chalk.green("✅") : chalk.dim("⬚");
    console.log(`  ${icon} ${engine.displayName} — ${engine.focus}`);
    if (!avail) {
      console.log(chalk.dim(`     Install: ${engine.installInstructions()}`));
    }
    availability.push({ engine, available: avail });
  }

  const availableEngines = availability.filter(a => a.available);
  console.log(chalk.dim(`\n  ${availableEngines.length}/${engines.length} engines available\n`));

  // Run available engines in parallel
  console.log(chalk.bold("⏳ Scanning...\n"));
  const results: EngineResult[] = await Promise.all(
    availability.map(async ({ engine, available }) => {
      if (!available) {
        return {
          engine: engine.id,
          displayName: engine.displayName,
          available: false,
          findings: null,
          error: `Not installed`,
          focus: engine.focus,
        };
      }
      const result = await engine.scan(targetDir);
      const findingCount = result.findings?.length ?? 0;
      const icon = result.error ? chalk.red("❌") : chalk.green("✅");
      console.log(`  ${icon} ${engine.displayName}: ${findingCount} findings (${result.durationMs}ms)`);
      return result;
    }),
  );

  // Aggregate — deduplicate overlapping engines
  // Skill Vetter internally runs aguara, so if both are active,
  // remove skill-vetter findings that duplicate aguara findings
  let allFindings = results
    .filter(r => r.findings)
    .flatMap(r => r.findings!);

  const hasAguara = results.some(r => r.engine === "aguara" && r.available && r.findings);
  const hasSkillVetter = results.some(r => r.engine === "skill-vetter" && r.available && r.findings);
  if (hasAguara && hasSkillVetter) {
    // Remove skill-vetter aguara-sourced findings (they duplicate the direct aguara engine)
    const aguaraKeys = new Set(
      allFindings.filter(f => f.engine === "aguara").map(f => `${f.file}:${f.line}`)
    );
    allFindings = allFindings.filter(f => {
      if (f.engine !== "skill-vetter") return true;
      // Keep non-aguara skill-vetter findings (secrets, structure checks)
      if (!f.file || !f.line) return true;
      return !aguaraKeys.has(`${f.file}:${f.line}`);
    });
  }

  const crossValidated = crossValidate(allFindings, results.filter(r => r.available).length);

  return {
    target: targetDir,
    engines: results,
    crossValidated,
    allFindings,
    totalEngines: engines.length,
    availableEngines: availableEngines.length,
    durationMs: Date.now() - start,
  };
}

/**
 * Cross-validate findings across engines.
 * Group findings by normalized key (file + approximate line + category).
 */
function crossValidate(findings: EngineFinding[], totalEngines: number): CrossValidatedFinding[] {
  const groups = new Map<string, { finding: EngineFinding; engines: Set<string> }>();

  for (const f of findings) {
    // Normalize key: file + line bucket (within 3 lines) + category
    const lineBucket = f.line ? Math.floor(f.line / 3) * 3 : 0;
    const category = normalizeCategory(f.rule, f.message);
    const key = `${f.file}:${lineBucket}:${category}`;

    if (!groups.has(key)) {
      groups.set(key, { finding: f, engines: new Set() });
    }
    groups.get(key)!.engines.add(f.engine);
  }

  return [...groups.entries()]
    .filter(([_, v]) => v.engines.size > 1) // Only cross-validated (2+ engines)
    .map(([key, v]) => ({
      key,
      file: v.finding.file,
      line: v.finding.line,
      severity: v.finding.severity,
      message: v.finding.message,
      detectedBy: [...v.engines],
      totalEngines,
      agreement: v.engines.size / totalEngines,
    }))
    .sort((a, b) => b.agreement - a.agreement || severityRank(a.severity) - severityRank(b.severity));
}

/**
 * Normalize rule/message into broad categories for cross-engine matching.
 */
function normalizeCategory(rule: string, message: string): string {
  const combined = `${rule} ${message}`.toLowerCase();
  if (/prompt.?inject|injection|override|ignore.*instruct|system.*prompt/i.test(combined)) return "prompt-injection";
  if (/eval|exec|backdoor|command.*inject|child_process|spawn|code.*gen|dynamic.*exec/i.test(combined)) return "code-execution";
  if (/exfil|data.*leak|sensitive.*send|credential.*http|phone.*home/i.test(combined)) return "data-exfil";
  if (/secret|api.?key|token|credential|password|hardcod|private.?key/i.test(combined)) return "credentials";
  if (/ssrf|request.*forg|url.*construct|http.*downgrad/i.test(combined)) return "ssrf";
  if (/supply.?chain|hijack|tamper|config.*modify|config.*tamper/i.test(combined)) return "supply-chain";
  if (/obfuscat|encode|pack|minif|unicode.*escape/i.test(combined)) return "obfuscation";
  if (/env.*var|process\.env|environ|env.*leak/i.test(combined)) return "env-access";
  if (/intercept|hook|monkey.?patch|tool.*output/i.test(combined)) return "interception";
  if (/uri.*manip|resource.*uri|path.*travers/i.test(combined)) return "path-traversal";
  if (/shell|dangerous.*command|rm\s+-rf/i.test(combined)) return "dangerous-commands";
  if (/mcp|remote.*server|non.?localhost/i.test(combined)) return "mcp-config";
  if (/regex|redos|re.*inject/i.test(combined)) return "regex-injection";
  return "other";
}

function severityRank(s: string): number {
  if (s === "high") return 0;
  if (s === "medium") return 1;
  if (s === "low") return 2;
  return 3;
}

/**
 * Print aggregated report.
 */
export function printAggregatedReport(result: AggregatedResult): void {
  const divider = chalk.dim("─".repeat(60));

  console.log();
  console.log(divider);
  console.log(chalk.bold("🛡️  AgentShield Multi-Engine Risk Report"));
  console.log(divider);
  console.log(chalk.dim(`📁 Target:   ${result.target}`));
  console.log(chalk.dim(`🔧 Engines:  ${result.availableEngines}/${result.totalEngines} active`));
  console.log(chalk.dim(`⏱  Time:     ${result.durationMs}ms`));
  console.log(divider);

  // Engine profiles
  console.log(chalk.bold("\n📋 Engine Profiles\n"));
  for (const engine of result.engines) {
    const icon = engine.available
      ? (engine.findings ? chalk.green("✅") : chalk.red("❌"))
      : chalk.dim("⬚");
    const count = engine.findings?.length ?? 0;
    const countStr = engine.available
      ? (engine.error ? chalk.red("error") : `${count} findings`)
      : chalk.dim("not installed");
    console.log(`  ${icon} ${chalk.bold(engine.displayName)} (${countStr})`);
    console.log(chalk.dim(`     ${engine.focus}`));
  }

  // Cross-validated findings (the most valuable part)
  if (result.crossValidated.length > 0) {
    console.log(chalk.bold("\n🔗 Cross-Engine Validation\n"));
    console.log(chalk.dim("  Findings confirmed by multiple engines have higher confidence.\n"));

    for (const cv of result.crossValidated) {
      const ratio = `${cv.detectedBy.length}/${cv.totalEngines}`;
      const color = cv.agreement >= 0.66 ? chalk.red : cv.agreement >= 0.5 ? chalk.yellow : chalk.green;
      const loc = cv.line ? `${cv.file}:${cv.line}` : cv.file;

      console.log(color(`  ${cv.severity.toUpperCase()} [${ratio} engines] ${loc}`));
      console.log(chalk.dim(`    ${cv.message}`));
      console.log(chalk.dim(`    Detected by: ${cv.detectedBy.join(" · ")}`));
      console.log();
    }
  }

  // Per-engine findings summary
  console.log(chalk.bold("📊 Findings by Engine\n"));
  for (const engine of result.engines) {
    if (!engine.findings || engine.findings.length === 0) continue;
    const high = engine.findings.filter(f => f.severity === "high").length;
    const med = engine.findings.filter(f => f.severity === "medium").length;
    const low = engine.findings.filter(f => f.severity === "low").length;

    console.log(`  ${chalk.bold(engine.displayName)}: ${engine.findings.length} total`);
    const parts: string[] = [];
    if (high > 0) parts.push(chalk.red(`${high} high`));
    if (med > 0) parts.push(chalk.yellow(`${med} medium`));
    if (low > 0) parts.push(chalk.green(`${low} low`));
    console.log(`    ${parts.join(", ")}`);
    console.log();
  }

  // Unique findings per engine
  const uniqueByEngine = new Map<string, EngineFinding[]>();
  for (const f of result.allFindings) {
    const key = `${f.file}:${Math.floor((f.line || 0) / 5) * 5}:${normalizeCategory(f.rule, f.message)}`;
    const isShared = result.crossValidated.some(cv => cv.key === key);
    if (!isShared) {
      if (!uniqueByEngine.has(f.engine)) uniqueByEngine.set(f.engine, []);
      uniqueByEngine.get(f.engine)!.push(f);
    }
  }

  if (uniqueByEngine.size > 0) {
    console.log(chalk.bold("🔍 Unique Findings (only one engine detected)\n"));
    for (const [engineId, findings] of uniqueByEngine) {
      const engine = result.engines.find(e => e.engine === engineId);
      const high = findings.filter(f => f.severity === "high").slice(0, 3);
      if (high.length > 0) {
        console.log(`  ${chalk.bold(engine?.displayName || engineId)} unique:`);
        for (const f of high) {
          const loc = f.line ? `${f.file}:${f.line}` : f.file;
          console.log(chalk.yellow(`    ${loc} — ${f.message}`));
        }
        console.log();
      }
    }
  }

  console.log(divider);
  console.log();
}
