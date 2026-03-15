import chalk from "chalk";
import type { ScanResult, Finding, ScoreResult } from "../types.js";
import { getRuleReference, groupByOwasp } from "../references.js";

export interface ReportOptions {
  showScore?: boolean;
  showFp?: boolean;
  lang?: "zh" | "en";
}

// ─── 风险类别的人话翻译 ───
const RISK_NAMES_ZH: Record<string, { name: string; desc: string }> = {
  "skill-hijack": { name: "🔴 插件劫持风险", desc: "代码试图修改 AI 的配置、注入指令或覆盖其他插件的行为" },
  "backdoor": { name: "🔴 后门执行风险", desc: "代码使用了 eval/exec 等动态执行方式，可能被利用来运行恶意代码" },
  "reverse-shell": { name: "🔴 远程控制风险", desc: "代码建立了出站网络连接并关联到 shell，可能被远程控制" },
  "data-exfil": { name: "⚠️ 数据外泄风险", desc: "代码读取了敏感数据并通过网络发送，可能泄露你的隐私信息" },
  "env-leak": { name: "⚠️ 环境变量泄露", desc: "代码读取了环境变量（如 API 密钥）并发送了网络请求" },
  "sensitive-read": { name: "⚠️ 敏感文件访问", desc: "代码试图访问 SSH 密钥、AWS 凭证等敏感文件" },
  "credential-hardcode": { name: "⚠️ 硬编码凭证", desc: "代码中直接写入了密钥、Token 等敏感信息" },
  "prompt-injection": { name: "⚠️ Prompt 注入风险", desc: "代码包含可能覆盖 AI 指令的内容，可能改变 AI 的行为" },
  "obfuscation": { name: "⚠️ 代码混淆", desc: "代码经过混淆处理，难以审查其真实意图" },
  "network-ssrf": { name: "ℹ️ 网络请求风险", desc: "代码动态构造 URL 发起请求，可能被利用访问内部服务" },
  "tool-shadowing": { name: "⚠️ 工具冲突", desc: "存在同名工具，可能导致 AI 调用了错误的工具" },
  "phone-home": { name: "⚠️ 定期回传", desc: "代码定期向外部服务器发送数据" },
  "crypto-mining": { name: "🔴 挖矿行为", desc: "代码包含加密货币挖矿相关的代码" },
  "privilege": { name: "ℹ️ 权限不匹配", desc: "实际行为超出了声明的权限范围" },
  "skill-risks": { name: "ℹ️ 插件功能风险", desc: "插件涉及网络请求、文件操作等需关注的功能" },
  "mcp-runtime": { name: "ℹ️ MCP 运行时风险", desc: "MCP 服务端存在安全配置问题" },
  "mcp-manifest": { name: "ℹ️ MCP 配置风险", desc: "MCP 的权限配置过于宽泛" },
};

const SEVERITY_ZH: Record<string, string> = {
  high: "🔴 高风险",
  medium: "⚠️ 中等风险",
  low: "ℹ️ 低风险",
};

export function printReport(result: ScanResult, opts: ReportOptions = {}): void {
  const { target, filesScanned, linesScanned, findings, scoreResult, duration } = result;
  const realFindings = findings.filter(f => !f.possibleFalsePositive);

  const divider = chalk.dim("═".repeat(55));
  const thinDiv = chalk.dim("─".repeat(55));

  console.log();
  console.log(divider);
  console.log(chalk.bold("🛡️  安全扫描报告"));
  console.log(divider);
  console.log();
  console.log(chalk.dim(`📁 扫描目标:  ${target}`));
  console.log(chalk.dim(`📄 扫描范围:  ${filesScanned} 个文件，${linesScanned.toLocaleString()} 行代码`));
  console.log(chalk.dim(`⏱  扫描耗时:  ${duration}ms`));
  console.log();

  if (realFindings.length === 0) {
    console.log(chalk.green.bold("✅ 扫描完成，未发现安全风险。"));
    console.log();
    console.log(divider);
    return;
  }

  // ─── 风险总览 ───
  const high = realFindings.filter(f => f.severity === "high").length;
  const medium = realFindings.filter(f => f.severity === "medium").length;
  const low = realFindings.filter(f => f.severity === "low").length;

  console.log(thinDiv);
  console.log(chalk.bold("📊 风险总览"));
  console.log(thinDiv);
  console.log();
  if (high > 0) console.log(chalk.red(`  🔴 ${high} 个高风险`));
  if (medium > 0) console.log(chalk.yellow(`  ⚠️  ${medium} 个中等风险`));
  if (low > 0) console.log(chalk.green(`  ℹ️  ${low} 个低风险`));
  console.log();

  // ─── 按规则分组，用人话描述 ───
  const byRule = new Map<string, Finding[]>();
  for (const f of realFindings) {
    if (!byRule.has(f.rule)) byRule.set(f.rule, []);
    byRule.get(f.rule)!.push(f);
  }

  // Sort: high first, then medium, then low
  const sortedRules = [...byRule.entries()].sort((a, b) => {
    return sevNum(a[1][0]!.severity) - sevNum(b[1][0]!.severity);
  });

  console.log(thinDiv);
  console.log(chalk.bold("📋 发现的风险"));
  console.log(thinDiv);
  console.log();

  for (const [rule, ruleFindings] of sortedRules) {
    const info = RISK_NAMES_ZH[rule];
    const sev = ruleFindings[0]!.severity;
    const ref = getRuleReference(rule);

    // 风险名称（人话）
    const riskName = info?.name || SEVERITY_ZH[sev] || "ℹ️ 其他风险";
    const riskDesc = info?.desc || ref.riskDescription;

    const colorize = sev === "high" ? chalk.red : sev === "medium" ? chalk.yellow : chalk.green;
    console.log(colorize.bold(`${riskName}（${ruleFindings.length} 处）`));
    console.log(chalk.dim(`  ${riskDesc}`));

    // 显示标准引用但不作为主体
    const refs: string[] = [];
    if (ref.owasp) refs.push(`OWASP ${ref.owasp.id}`);
    if (ref.cwe) refs.push(ref.cwe.id);
    if (refs.length > 0) {
      console.log(chalk.dim(`  参考标准: ${refs.join(" · ")}`));
    }
    console.log();

    // 具体位置（最多显示 5 个）
    const show = ruleFindings.slice(0, 5);
    for (const f of show) {
      const loc = f.line ? `${f.file}:${f.line}` : f.file;
      console.log(chalk.dim(`  📍 ${loc}`));
      if (f.evidence) console.log(chalk.dim(`     ${f.evidence.slice(0, 80)}`));
    }
    if (ruleFindings.length > 5) {
      console.log(chalk.dim(`  ... 还有 ${ruleFindings.length - 5} 处`));
    }
    console.log();
  }

  // FP
  const fpCount = findings.length - realFindings.length;
  if (fpCount > 0) {
    console.log(chalk.dim(`ℹ️  另有 ${fpCount} 条可能的误报已自动隐藏`));
    console.log();
  }

  // Score (optional)
  if (opts.showScore && scoreResult) {
    console.log(thinDiv);
    console.log(chalk.bold("📊 参考分数") + chalk.dim("（仅供参考，非权威评判）"));
    console.log();
    const s = scoreResult.overall;
    const c = s >= 90 ? chalk.green : s >= 75 ? chalk.yellow : s >= 50 ? chalk.hex("#FF8800") : chalk.red;
    console.log(`  ${c.bold(`${s}/100`)}`);
    console.log();
  }

  console.log(divider);
  console.log();
}

function sevNum(s: string): number {
  if (s === "high") return 0;
  if (s === "medium") return 1;
  return 2;
}
