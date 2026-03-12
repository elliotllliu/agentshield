#!/usr/bin/env node

import { Command } from "commander";
import { resolve, join } from "path";
import { existsSync, statSync, writeFileSync, watch as fsWatch, mkdirSync } from "fs";
import { scan } from "./scanner/index.js";
import { printReport } from "./reporter/terminal.js";
import { printJsonReport } from "./reporter/json.js";
import { generateBadgeSvg, generateBadgeMarkdown } from "./reporter/badge.js";
import { discoverAgents, printDiscovery } from "./discover.js";
import { getLlmConfigFromEnv, runLlmAnalysis } from "./llm-analyzer.js";
import { DEFAULT_CONFIG, DEFAULT_IGNORE } from "./config.js";

const program = new Command();

program
  .name("agentshield")
  .description("Security scanner for AI agent skills, MCP servers, and plugins")
  .version("0.1.0");

program
  .command("scan")
  .description("Scan a skill/plugin directory for security issues")
  .argument("<directory>", "Target directory to scan")
  .option("--json", "Output results as JSON")
  .option("--fail-under <score>", "Exit with code 1 if score is below threshold", parseInt)
  .option("--disable <rules>", "Comma-separated rules to disable")
  .option("--enable <rules>", "Comma-separated rules to enable (only these)")
  .option("--llm", "Enable LLM-based deep prompt injection analysis (requires API key in env)")
  .action(async (directory: string, options: { json?: boolean; failUnder?: number; disable?: string; enable?: string; llm?: boolean }) => {
    const target = resolve(directory);

    if (!existsSync(target) || !statSync(target).isDirectory()) {
      console.error(`Error: "${directory}" is not a valid directory`);
      process.exit(1);
    }

    const configOverride: Record<string, unknown> = {};
    if (options.disable || options.enable) {
      configOverride.rules = {};
      if (options.disable) {
        (configOverride.rules as Record<string, string[]>).disable = options.disable.split(",").map((s) => s.trim());
      }
      if (options.enable) {
        (configOverride.rules as Record<string, string[]>).enable = options.enable.split(",").map((s) => s.trim());
      }
    }

    const result = scan(target, configOverride);

    // LLM-based deep analysis (optional)
    if (options.llm) {
      const llmConfig = getLlmConfigFromEnv();
      if (!llmConfig) {
        console.error("Error: --llm requires an API key. Set OPENAI_API_KEY, ANTHROPIC_API_KEY, or AGENTSHIELD_API_KEY.");
        process.exit(1);
      }
      console.error(`🤖 Running LLM analysis with ${llmConfig.model}...`);
      const { collectFiles } = await import("./scanner/files.js");
      const files = collectFiles(target);
      const llmFindings = await runLlmAnalysis(files, llmConfig);
      result.findings.push(...llmFindings);
      // Recalculate score
      const { computeScore } = await import("./score.js");
      result.score = computeScore(result.findings);
    }

    if (options.json) {
      printJsonReport(result);
    } else {
      printReport(result);
    }

    const threshold = options.failUnder ?? result.score;
    if (options.failUnder !== undefined && result.score < options.failUnder) {
      process.exit(1);
    }
  });

program
  .command("init")
  .description("Generate .agentshield.yml and .agentshieldignore config files")
  .argument("[directory]", "Target directory", ".")
  .action((directory: string) => {
    const target = resolve(directory);

    if (!existsSync(target)) {
      mkdirSync(target, { recursive: true });
    }
    const configPath = join(target, ".agentshield.yml");
    const ignorePath = join(target, ".agentshieldignore");

    if (existsSync(configPath)) {
      console.log(`⚠️  ${configPath} already exists, skipping`);
    } else {
      writeFileSync(configPath, DEFAULT_CONFIG);
      console.log(`✅ Created ${configPath}`);
    }

    if (existsSync(ignorePath)) {
      console.log(`⚠️  ${ignorePath} already exists, skipping`);
    } else {
      writeFileSync(ignorePath, DEFAULT_IGNORE);
      console.log(`✅ Created ${ignorePath}`);
    }
  });

program
  .command("watch")
  .description("Watch a directory and re-scan on file changes")
  .argument("<directory>", "Target directory to watch")
  .option("--json", "Output results as JSON")
  .action((directory: string, options: { json?: boolean }) => {
    const target = resolve(directory);
    if (!existsSync(target) || !statSync(target).isDirectory()) {
      console.error(`Error: "${directory}" is not a valid directory`);
      process.exit(1);
    }

    console.log(`👀 Watching ${target} for changes... (Ctrl+C to stop)\n`);

    const runScan = () => {
      console.clear();
      console.log(`👀 Watching ${target} — last scan: ${new Date().toLocaleTimeString()}\n`);
      const result = scan(target);
      if (options.json) {
        printJsonReport(result);
      } else {
        printReport(result);
      }
    };

    // Initial scan
    runScan();

    // Watch for changes
    try {
      const watcher = fsWatch(target, { recursive: true }, () => {
        runScan();
      });
      process.on("SIGINT", () => {
        watcher.close();
        process.exit(0);
      });
    } catch {
      console.error("⚠️  fs.watch recursive not supported on this platform. Use: nodemon --exec 'agentshield scan .'");
    }
  });

program
  .command("compare")
  .description("Compare security scores between two directories or git refs")
  .argument("<dirA>", "First directory")
  .argument("<dirB>", "Second directory")
  .option("--json", "Output as JSON")
  .action((dirA: string, dirB: string, options: { json?: boolean }) => {
    const targetA = resolve(dirA);
    const targetB = resolve(dirB);

    for (const [label, dir] of [["A", targetA], ["B", targetB]] as const) {
      if (!existsSync(dir) || !statSync(dir).isDirectory()) {
        console.error(`Error: directory ${label} "${dir}" is not valid`);
        process.exit(1);
      }
    }

    const resultA = scan(targetA);
    const resultB = scan(targetB);

    if (options.json) {
      console.log(JSON.stringify({
        before: { target: resultA.target, score: resultA.score, findings: resultA.findings.length },
        after: { target: resultB.target, score: resultB.score, findings: resultB.findings.length },
        delta: resultB.score - resultA.score,
      }, null, 2));
      return;
    }

    console.log("\n🔄 AgentShield Comparison\n");
    console.log(`  A: ${dirA} — Score: ${resultA.score}/100 (${resultA.findings.length} findings)`);
    console.log(`  B: ${dirB} — Score: ${resultB.score}/100 (${resultB.findings.length} findings)`);
    console.log();

    const delta = resultB.score - resultA.score;
    if (delta > 0) {
      console.log(`  ✅ Improved by ${delta} points`);
    } else if (delta < 0) {
      console.log(`  🔴 Degraded by ${Math.abs(delta)} points`);
    } else {
      console.log(`  ➡️  No change`);
    }

    // Show new findings in B that aren't in A
    const aKeys = new Set(resultA.findings.map((f) => `${f.rule}:${f.file}:${f.line}`));
    const newFindings = resultB.findings.filter((f) => !aKeys.has(`${f.rule}:${f.file}:${f.line}`));
    const fixedFindings = resultA.findings.filter((f) => {
      const bKeys = new Set(resultB.findings.map((bf) => `${bf.rule}:${bf.file}:${bf.line}`));
      return !bKeys.has(`${f.rule}:${f.file}:${f.line}`);
    });

    if (newFindings.length > 0) {
      console.log(`\n  🆕 New findings (${newFindings.length}):`);
      for (const f of newFindings.slice(0, 10)) {
        console.log(`     ${f.file}${f.line ? `:${f.line}` : ""} — [${f.rule}] ${f.message}`);
      }
    }
    if (fixedFindings.length > 0) {
      console.log(`\n  ✅ Fixed (${fixedFindings.length}):`);
      for (const f of fixedFindings.slice(0, 10)) {
        console.log(`     ${f.file}${f.line ? `:${f.line}` : ""} — [${f.rule}] ${f.message}`);
      }
    }
    console.log();
  });

program
  .command("badge")
  .description("Generate a security badge for your project")
  .argument("<directory>", "Target directory to scan")
  .option("--svg", "Output raw SVG")
  .option("--markdown", "Output markdown badge (default)")
  .option("-o, --output <file>", "Save SVG to file")
  .action((directory: string, options: { svg?: boolean; markdown?: boolean; output?: string }) => {
    const target = resolve(directory);
    if (!existsSync(target) || !statSync(target).isDirectory()) {
      console.error(`Error: "${directory}" is not a valid directory`);
      process.exit(1);
    }

    const result = scan(target);

    if (options.svg || options.output) {
      const svg = generateBadgeSvg(result);
      if (options.output) {
        writeFileSync(resolve(options.output), svg);
        console.log(`✅ Badge saved to ${options.output}`);
      } else {
        console.log(svg);
      }
    } else {
      // Default: markdown
      const md = generateBadgeMarkdown(result.score);
      console.log(md);
      console.log(`\nPaste this in your README.md to show the badge.`);
    }
  });

program
  .command("discover")
  .description("Discover installed AI agents, MCP servers, and skills on this machine")
  .action(() => {
    const agents = discoverAgents();
    printDiscovery(agents);
  });

// Default: if first arg looks like a directory, treat as scan
const args = process.argv.slice(2);
if (args.length > 0 && !args[0]!.startsWith("-") && !["scan", "init", "watch", "compare", "badge", "discover", "help"].includes(args[0]!)) {
  process.argv.splice(2, 0, "scan");
}

program.parse();
