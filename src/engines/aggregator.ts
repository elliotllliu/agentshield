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
 * Print aggregated report — 会诊模式
 * Each engine gives its conclusion, then a comprehensive summary.
 */
export function printAggregatedReport(result: AggregatedResult): void {
  const divider = chalk.bold("━".repeat(50));
  const thinDiv = chalk.dim("─".repeat(50));

  // Engine icons
  const ICONS: Record<string, string> = {
    agentshield: "🛡️",
    aguara: "🔍",
    semgrep: "🔎",
    "skill-vetter": "🔒",
    tencent: "🏢",
  };

  // Engine specialty descriptions in Chinese
  const SPECIALTY: Record<string, string> = {
    agentshield: "AI Agent 安全",
    aguara: "通用代码安全",
    semgrep: "代码质量与注入检测",
    "skill-vetter": "综合安全检查",
    tencent: "基础设施安全",
  };

  // Risk name mapping for common rules
  const RISK_ZH: Record<string, string> = {
    "prompt-injection": "Prompt 注入",
    "code-execution": "代码执行风险",
    "data-exfil": "数据外泄",
    "credentials": "硬编码凭证",
    "ssrf": "请求伪造",
    "supply-chain": "供应链风险",
    "obfuscation": "代码混淆",
    "env-access": "环境变量泄露",
    "interception": "工具输出拦截",
    "path-traversal": "路径遍历",
    "dangerous-commands": "危险命令",
    "mcp-config": "MCP 配置风险",
    "regex-injection": "正则注入",
  };

  console.log();
  console.log(divider);
  console.log(chalk.bold("🛡️  安全检测报告"));
  console.log(divider);
  console.log();
  console.log(chalk.dim(`📁 检测对象:  ${result.target}`));
  console.log(chalk.dim(`🔧 检测引擎:  ${result.availableEngines} 个独立扫描器`));
  console.log(chalk.dim(`⏱  总耗时:    ${(result.durationMs / 1000).toFixed(1)}s`));
  console.log();

  // ─── 各方检测结论 ───
  console.log(thinDiv);
  console.log(chalk.bold("🔍 各方检测结论"));
  console.log(thinDiv);
  console.log();

  for (const engine of result.engines) {
    const icon = ICONS[engine.engine] || "🔧";
    const specialty = SPECIALTY[engine.engine] || engine.focus;

    if (!engine.available) {
      console.log(chalk.dim(`${icon} ${engine.displayName} — ${specialty}`));
      console.log(chalk.dim(`   ⬚ 未安装`));
      console.log();
      continue;
    }

    if (engine.error || !engine.findings) {
      console.log(chalk.dim(`${icon} ${engine.displayName} — ${specialty}`));
      console.log(chalk.red(`   ❌ 检测出错`));
      console.log();
      continue;
    }

    const findings = engine.findings;
    const high = findings.filter(f => f.severity === "high").length;
    const med = findings.filter(f => f.severity === "medium").length;

    console.log(chalk.bold(`${icon} ${engine.displayName} — ${specialty}`));

    if (findings.length === 0) {
      console.log(chalk.green(`   结论: ✅ 未发现风险`));
    } else if (high > 0) {
      console.log(chalk.red(`   结论: 🔴 发现 ${high} 处高风险${med > 0 ? `，${med} 处中等` : ""}`));
    } else if (med > 0) {
      console.log(chalk.yellow(`   结论: ⚠️ 发现 ${med} 处需关注`));
    } else {
      console.log(chalk.green(`   结论: ℹ️ ${findings.length} 处低风险提示`));
    }

    // Show top findings (max 3, high/medium only for brevity)
    const important = findings
      .filter(f => f.severity === "high" || f.severity === "medium")
      .slice(0, 3);

    for (const f of important) {
      const cat = normalizeCategory(f.rule, f.message);
      const name = RISK_ZH[cat] || f.message.slice(0, 30);
      const loc = f.line ? `${f.file}:${f.line}` : f.file;
      console.log(chalk.dim(`   • ${name}`));
      if (loc) console.log(chalk.dim(`     📍 ${loc}`));
    }

    if (findings.length > important.length && important.length > 0) {
      const rest = findings.length - important.length;
      console.log(chalk.dim(`   • 另有 ${rest} 处低风险提示`));
    }

    console.log();
  }

  // ─── 综合结论（核心判断逻辑）───
  console.log(thinDiv);
  console.log(chalk.bold("📊 综合结论"));
  console.log(thinDiv);
  console.log();

  const allFindings = result.allFindings;
  const activeEngines = result.engines.filter(e => e.available && e.findings);
  const totalActive = activeEngines.length;

  // Count how many engines flagged each severity level
  const enginesWithHigh = activeEngines.filter(e => e.findings!.some(f => f.severity === "high")).length;
  const enginesWithMed = activeEngines.filter(e => e.findings!.some(f => f.severity === "medium")).length;
  const enginesClean = activeEngines.filter(e => e.findings!.length === 0).length;
  const enginesLowOnly = activeEngines.filter(e =>
    e.findings!.length > 0 && e.findings!.every(f => f.severity === "low" || f.severity === "info")
  ).length;

  // Smart synthesis: don't just take the worst — consider consensus
  if (enginesWithHigh >= 2) {
    // 2+ engines agree on high risk → genuinely concerning
    console.log(chalk.red.bold("🔴 多个引擎发现高风险，建议谨慎使用"));
    console.log(chalk.dim(`   ${enginesWithHigh}/${totalActive} 个引擎标记了高风险`));
  } else if (enginesWithHigh === 1 && enginesClean >= 2) {
    // Only 1 engine says high, but most others found nothing → likely false positive
    console.log(chalk.yellow.bold("⚠️ 单个引擎标记高风险，其余未发现问题"));
    console.log(chalk.dim(`   ${enginesClean}/${totalActive} 个引擎未检出风险，高风险标记可能为误报`));
    console.log(chalk.dim(`   建议人工确认标记项是否为正常功能`));
  } else if (enginesWithHigh === 1) {
    console.log(chalk.yellow.bold("⚠️ 存在争议，建议人工审查"));
    console.log(chalk.dim(`   1 个引擎标记高风险，其余引擎看法不一`));
  } else if (enginesWithMed >= 2) {
    // Multiple engines agree on medium → worth checking
    console.log(chalk.yellow.bold("⚠️ 多个引擎发现中等风险，建议检查后使用"));
    console.log(chalk.dim(`   ${enginesWithMed}/${totalActive} 个引擎标记了中等风险`));
  } else if (enginesWithMed === 1 && enginesClean >= 2) {
    // Only 1 engine says medium, most others clean → probably fine
    console.log(chalk.green.bold("✅ 整体安全，有少量提示"));
    console.log(chalk.dim(`   ${enginesClean}/${totalActive} 个引擎未检出风险`));
    console.log(chalk.dim(`   1 个引擎有中等风险标记，可选择性检查`));
  } else if (enginesWithMed === 1) {
    console.log(chalk.green.bold("ℹ️ 基本安全，有个别提示可关注"));
  } else if (enginesLowOnly > 0 && enginesClean > 0) {
    // Only low-risk findings, some engines clean
    console.log(chalk.green.bold("✅ 整体安全"));
    console.log(chalk.dim(`   ${enginesClean}/${totalActive} 个引擎未检出风险`));
    console.log(chalk.dim(`   少量低风险提示属于常规功能行为`));
  } else if (enginesClean === totalActive) {
    console.log(chalk.green.bold("✅ 所有引擎均未检出风险"));
  } else {
    console.log(chalk.green.bold("ℹ️ 仅有低风险提示，整体较安全"));
  }
  console.log();

  // Safe dimensions
  const safeCategories = [
    { name: "后门/远程控制", rules: ["backdoor", "reverse-shell"] },
    { name: "数据窃取外渗", rules: ["data-exfil"] },
    { name: "Prompt 指令注入", rules: ["prompt-injection", "multilang-injection"] },
    { name: "挖矿行为", rules: ["crypto-mining"] },
  ];

  const foundRules = new Set(allFindings.map(f => normalizeCategory(f.rule, f.message)));
  const safeOnes = safeCategories.filter(c => !c.rules.some(r => foundRules.has(r)));
  const riskyOnes = safeCategories.filter(c => c.rules.some(r => foundRules.has(r)));

  if (safeOnes.length > 0) {
    for (const s of safeOnes) {
      console.log(chalk.green(`  ✅ ${s.name} — ${activeEngines.length} 个引擎均未检出`));
    }
  }
  if (riskyOnes.length > 0) {
    for (const r of riskyOnes) {
      console.log(chalk.red(`  ⚠️ ${r.name} — 已检出风险`));
    }
  }
  console.log();

  // Suggestions
  if (enginesWithHigh > 0 || enginesWithMed > 0) {
    console.log(chalk.bold("💡 建议"));
    console.log();

    const suggestions = new Set<string>();
    for (const f of allFindings.filter(fi => fi.severity === "high" || fi.severity === "medium")) {
      const cat = normalizeCategory(f.rule, f.message);
      if (cat === "credentials" && !suggestions.has("cred")) {
        suggestions.add("cred");
        console.log(chalk.dim("  1. 移除或加密代码中的硬编码凭证"));
      } else if (cat === "env-access" && !suggestions.has("env")) {
        suggestions.add("env");
        console.log(chalk.dim(`  ${suggestions.size}. 检查环境变量的网络请求是否为正常 API 调用`));
      } else if (cat === "obfuscation" && !suggestions.has("obf")) {
        suggestions.add("obf");
        console.log(chalk.dim(`  ${suggestions.size}. 审查混淆代码的真实内容`));
      } else if (cat === "code-execution" && !suggestions.has("exec")) {
        suggestions.add("exec");
        console.log(chalk.dim(`  ${suggestions.size}. 检查动态代码执行是否必要`));
      } else if (cat === "interception" && !suggestions.has("intercept")) {
        suggestions.add("intercept");
        console.log(chalk.dim(`  ${suggestions.size}. 检查工具输出拦截是否为预期行为`));
      } else if (!suggestions.has(cat)) {
        suggestions.add(cat);
        const name = RISK_ZH[cat] || cat;
        console.log(chalk.dim(`  ${suggestions.size}. 检查 ${name} 相关代码`));
      }
    }
    console.log();
  }

  console.log(divider);
  console.log();
}
