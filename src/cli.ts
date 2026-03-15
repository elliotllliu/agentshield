#!/usr/bin/env node

import { Command } from "commander";
import { existsSync } from "fs";
import { resolve } from "path";
import { aggregateScan, printAggregatedReport } from "./engines/aggregator.js";

const program = new Command();

program
  .name("agent-shield")
  .description("🛡️ AI Agent 安全扫描器 — 多引擎聚合检测 Skill / Plugin / MCP Server 安全风险")
  .version("0.15.0");

program
  .command("scan")
  .description("扫描目标目录，自动安装并运行所有引擎")
  .argument("<target>", "要扫描的目录路径")
  .option("--json", "JSON 输出")
  .option("--html", "生成 HTML 报告")
  .option("--sarif", "SARIF 输出（GitHub Code Scanning）")
  .option("-o, --output <path>", "输出文件路径")
  .option("--lang <lang>", "报告语言: zh（默认）或 en", "zh")
  .option("--score", "附带参考分数（可选）")
  .option("--show-fp", "显示可能的误报")
  .action(async (target: string, options: Record<string, unknown>) => {
    const targetPath = resolve(target);
    if (!existsSync(targetPath)) {
      console.error(`❌ 目录不存在: ${targetPath}`);
      process.exit(1);
    }

    try {
      // Always run all engines with auto-install
      const result = await aggregateScan(targetPath);

      if (options.json) {
        console.log(JSON.stringify(result, null, 2));
      } else if (options.html) {
        const { generateMultiEngineHtmlReport } = await import("./reporter/html.js");
        const htmlContent = generateMultiEngineHtmlReport(result, { lang: (options.lang as "zh" | "en") || "zh" });
        const outPath = (options.output as string) || "agentshield-report.html";
        const { writeFileSync } = await import("fs");
        writeFileSync(outPath, htmlContent);
        console.log(`📄 HTML 报告已保存: ${outPath}`);
      } else if (options.sarif) {
        const { scanToSarif } = await import("./reporter/sarif.js");
        // Run single-engine scan for SARIF (standardized format)
        const { scanDirectory } = await import("./scanner.js");
        const singleResult = scanDirectory(targetPath, {});
        const sarifResult = scanToSarif(singleResult);
        const output = JSON.stringify(sarifResult, null, 2);
        if (options.output) {
          const { writeFileSync } = await import("fs");
          writeFileSync(options.output as string, output);
          console.log(`📄 SARIF 报告已保存: ${options.output}`);
        } else {
          console.log(output);
        }
      } else {
        // Default: 会诊模式终端报告
        printAggregatedReport(result);
      }
    } catch (err) {
      console.error(`❌ 扫描出错: ${(err as Error).message}`);
      process.exit(1);
    }
  });

program.parse();
