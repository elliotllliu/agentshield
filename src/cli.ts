#!/usr/bin/env node

import { Command } from "commander";
import { resolve, join, basename } from "path";
import { existsSync, statSync, writeFileSync, watch as fsWatch, mkdirSync } from "fs";
import { scan } from "./scanner/index.js";
import { extractDifypkg, cleanupTemp, collectFiles } from "./scanner/files.js";
import { printReport } from "./reporter/terminal.js";
import { printJsonReport } from "./reporter/json.js";
import { generateBadgeSvg, generateBadgeMarkdown } from "./reporter/badge.js";
import { discoverAgents, printDiscovery } from "./discover.js";
import { getLlmConfigFromEnv, resolveAiConfig, runLlmAnalysis } from "./llm-analyzer.js";
import { aggregateScan, printAggregatedReport, listEngines } from "./engines/aggregator.js";
import { toSarif } from "./reporter/sarif.js";
import { generateHtmlReport } from "./reporter/html.js";
import { DEFAULT_CONFIG, DEFAULT_IGNORE, loadConfig } from "./config.js";
import { generateManifest, saveManifest, loadManifest, verifyManifest, hashFiles, contentHash } from "./provenance.js";
import { evaluatePolicy, getAgentPolicy, POLICY_PRESETS } from "./policy.js";
import { letterGrade } from "./score.js";

const program = new Command();

program
  .name("agent-shield")
  .description("Security scanner for AI agent skills, MCP servers, and plugins")
  .version("0.1.0");

program
  .command("scan")
  .description("Scan a skill/plugin directory for security risks")
  .argument("<directory>", "Target directory to scan")
  .option("--json", "Output results as JSON")
  .option("--score", "Show reference score (optional risk density metric)")
  .option("--engines <list>", "Multi-engine scan: all, or comma-separated (agentshield,aguara,tencent)")
  .option("--fail-under <score>", "Exit with code 1 if score is below threshold", parseInt)
  .option("--disable <rules>", "Comma-separated rules to disable")
  .option("--enable <rules>", "Comma-separated rules to enable (only these)")
  .option("--ai", "Enable AI-powered deep analysis (requires API key)")
  .option("--sarif", "Output results in SARIF format (GitHub Code Scanning compatible)")
  .option("--html", "Output results as an HTML report")
  .option("--output <file>", "Write output to file instead of stdout")
  .option("--provider <provider>", "AI provider: openai | anthropic | ollama (default: auto-detect)")
  .option("--model <model>", "AI model to use (e.g. gpt-4o, claude-sonnet-4-20250514, llama3)")
  .action(async (directory: string, options: { json?: boolean; sarif?: boolean; html?: boolean; output?: string; failUnder?: number; disable?: string; enable?: string; ai?: boolean; provider?: string; model?: string; engines?: string }) => {
    const target = resolve(directory);
    let scanTarget = target;
    let tempDir: string | null = null;

    // Multi-engine mode
    if ((options as any).engines) {
      const engineStr = (options as any).engines as string;
      if (engineStr === "list") {
        const engines = listEngines();
        console.log("\n🔧 Available Engines\n");
        for (const engine of engines) {
          const avail = await engine.isAvailable();
          const icon = avail ? "✅" : "⬚";
          console.log(`  ${icon} ${engine.displayName} (${engine.id})`);
          console.log(`     ${engine.focus}`);
          if (!avail) console.log(`     Install: ${engine.installInstructions()}`);
          console.log();
        }
        return;
      }
      const engineIds = engineStr === "all" ? undefined : engineStr.split(",").map((s: string) => s.trim());
      const aggResult = await aggregateScan(target, engineIds);
      if (options.json) {
        console.log(JSON.stringify(aggResult, null, 2));
      } else {
        printAggregatedReport(aggResult);
      }
      return;
    }

    // Support .difypkg files (zip archives)
    if (target.endsWith(".difypkg") || target.endsWith(".zip")) {
      if (!existsSync(target) || !statSync(target).isFile()) {
        console.error(`Error: "${directory}" is not a valid file`);
        process.exit(1);
      }
      tempDir = extractDifypkg(target);
      scanTarget = tempDir;
    } else if (!existsSync(target) || !statSync(target).isDirectory()) {
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

    const result = scan(scanTarget, configOverride);

    // AI-powered deep analysis (optional)
    if (options.ai) {
      const llmConfig = resolveAiConfig(options.provider, options.model);
      if (!llmConfig) {
        console.error("Error: --ai requires an API key. Set OPENAI_API_KEY, ANTHROPIC_API_KEY, or use --provider ollama.");
        process.exit(1);
      }
      const providerLabel = options.provider || "auto";
      console.error(`🤖 Running AI analysis (${providerLabel}/${llmConfig.model})...`);
      
      const files = collectFiles(target);
      const llmFindings = await runLlmAnalysis(files, llmConfig);
      result.findings.push(...llmFindings);
      const { computeScore, computeScoreV2 } = await import("./score.js");
      const { totalLines } = await import("./scanner/files.js");
      result.score = computeScore(result.findings);
      const projectMeta = { fileList: files.map(f => f.relativePath), totalLines: totalLines(files), totalFiles: files.length, hasNetworkCalls: result.findings.some(f => !f.possibleFalsePositive && ["data-exfil","phone-home","network-ssrf"].includes(f.rule)) };
      result.scoreResult = computeScoreV2(result.findings, projectMeta);

    }

    if (options.json) {
      const out = JSON.stringify(result, null, 2);
      if (options.output) { writeFileSync(options.output, out); console.error(`📄 Written to ${options.output}`); }
      else printJsonReport(result);
    } else if (options.sarif) {
      const out = toSarif(result);
      if (options.output) { writeFileSync(options.output, out); console.error(`📄 SARIF written to ${options.output}`); }
      else console.log(out);
    } else if (options.html) {
      const out = generateHtmlReport(result);
      const file = options.output || "agent-shield-report.html";
      writeFileSync(file, out);
      console.error(`📄 HTML report written to ${file}`);
    } else {
      printReport(result, { showScore: (options as any).score, lang: (options as any).lang || "zh" });
    }

    const threshold = options.failUnder ?? result.score;
    if (options.failUnder !== undefined && result.score < options.failUnder) {
      if (tempDir) cleanupTemp(tempDir);
      process.exit(1);
    }
    if (tempDir) cleanupTemp(tempDir);
  });

program
  .command("init")
  .description("Generate .agent-shield.yml and .agent-shieldignore config files")
  .argument("[directory]", "Target directory", ".")
  .action((directory: string) => {
    const target = resolve(directory);

    if (!existsSync(target)) {
      mkdirSync(target, { recursive: true });
    }
    const configPath = join(target, ".agent-shield.yml");
    const ignorePath = join(target, ".agent-shieldignore");

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
  .description("Watch a directory and re-scan on file changes (with content hash dedup)")
  .argument("<directory>", "Target directory to watch")
  .option("--json", "Output results as JSON")
  .option("--verify", "Verify against saved provenance manifest on each scan")
  .option("--agent <name>", "Evaluate against agent-specific security policy")
  .action((directory: string, options: { json?: boolean; verify?: boolean; agent?: string }) => {
    const target = resolve(directory);
    if (!existsSync(target) || !statSync(target).isDirectory()) {
      console.error(`Error: "${directory}" is not a valid directory`);
      process.exit(1);
    }

    console.log(`👀 Watching ${target} for changes... (Ctrl+C to stop)\n`);

    let lastHash = "";

    const runScan = () => {
      const result = scan(target);

      // Content hash dedup — skip if nothing changed
      
      const files = collectFiles(target);
      const currentHashes = hashFiles(files);
      const currentHash = contentHash(currentHashes);

      if (currentHash === lastHash) return; // no actual change
      lastHash = currentHash;

      console.clear();
      console.log(`👀 Watching ${target} — last scan: ${new Date().toLocaleTimeString()}\n`);

      if (options.json) {
        printJsonReport(result);
      } else {
        printReport(result, { showScore: (options as any).score, lang: (options as any).lang || "zh" });
      }

      // Provenance verification
      if (options.verify) {
        const manifest = loadManifest(target);
        if (manifest) {
          const verification = verifyManifest(files, manifest);
          if (!verification.valid) {
            console.log("\n⚠️  Provenance changed since last manifest:");
            if (verification.changed.length) console.log(`   Modified: ${verification.changed.join(", ")}`);
            if (verification.added.length) console.log(`   Added: ${verification.added.join(", ")}`);
            if (verification.removed.length) console.log(`   Removed: ${verification.removed.join(", ")}`);
          } else {
            console.log("\n✅ Provenance verified — no unexpected changes");
          }
        }
      }

      // Agent policy evaluation
      if (options.agent) {
        const config = loadConfig(target);
        const policy = getAgentPolicy(config, options.agent);
        if (policy) {
          const evaluation = evaluatePolicy(result, policy);
          if (evaluation.pass) {
            console.log(`\n✅ Policy check passed for agent "${options.agent}"`);
          } else {
            console.log(`\n🚫 Policy FAILED for agent "${options.agent}":`);
            evaluation.reasons.forEach((r) => console.log(`   - ${r}`));
          }
        }
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
      console.error("⚠️  fs.watch recursive not supported on this platform. Use: nodemon --exec 'agent-shield scan .'");
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
  .command("install-check")
  .description("Scan a remote skill/plugin before installing it")
  .argument("<url>", "GitHub URL, npm package, or local path")
  .option("--json", "Output results as JSON")
  .option("--fail-under <score>", "Exit with code 1 if score is below threshold", parseInt)
  .option("--ai", "Enable AI-powered deep analysis")
  .option("--provider <provider>", "AI provider: openai | anthropic | ollama")
  .option("--model <model>", "AI model to use")
  .action(async (url: string, options: { json?: boolean; failUnder?: number; ai?: boolean; provider?: string; model?: string }) => {
    const { execSync } = await import("child_process");
    const { mkdtempSync, rmSync, existsSync: ex } = await import("fs");
    const { tmpdir } = await import("os");
    const { join: pjoin } = await import("path");

    let scanDir: string;
    let tempDir: string | null = null;
    let source = url;

    // Determine source type
    const isGitHub = /^https?:\/\/(www\.)?github\.com\//.test(url) || /^[\w-]+\/[\w.-]+$/.test(url);
    const isNpm = url.startsWith("@") || (!url.includes("/") && !url.includes(".") && !ex(url));

    if (isGitHub) {
      // GitHub URL or owner/repo shorthand
      const repoUrl = url.startsWith("http") ? url : `https://github.com/${url}`;
      tempDir = mkdtempSync(pjoin(tmpdir(), "agent-shield-check-"));
      console.error(`📥 Cloning ${repoUrl}...`);
      try {
        execSync(`git clone --depth 1 ${repoUrl} ${tempDir}/repo`, { stdio: "pipe" });
      } catch {
        console.error(`❌ Failed to clone ${repoUrl}`);
        if (tempDir) rmSync(tempDir, { recursive: true, force: true });
        process.exit(1);
      }
      scanDir = pjoin(tempDir, "repo");
      source = repoUrl;
    } else if (isNpm) {
      // npm package
      tempDir = mkdtempSync(pjoin(tmpdir(), "agent-shield-check-"));
      console.error(`📥 Downloading npm package ${url}...`);
      try {
        execSync(`npm pack ${url} --pack-destination ${tempDir}`, { stdio: "pipe" });
        const tgz = execSync(`ls ${tempDir}/*.tgz`).toString().trim();
        execSync(`tar -xzf ${tgz} -C ${tempDir}`, { stdio: "pipe" });
        scanDir = pjoin(tempDir, "package");
      } catch {
        console.error(`❌ Failed to download ${url} from npm`);
        if (tempDir) rmSync(tempDir, { recursive: true, force: true });
        process.exit(1);
      }
      source = `npm:${url}`;
    } else {
      // Local path or .difypkg
      const target = resolve(url);
      if (target.endsWith(".difypkg") || target.endsWith(".zip")) {
        tempDir = extractDifypkg(target);
        scanDir = tempDir;
      } else if (ex(target) && statSync(target).isDirectory()) {
        scanDir = target;
      } else {
        console.error(`❌ "${url}" is not a valid URL, npm package, or directory`);
        process.exit(1);
      }
      source = target;
    }

    console.error(`🔍 Scanning ${source}...\n`);
    const result = scan(scanDir);

    // AI analysis if requested
    if (options.ai) {
      const llmConfig = resolveAiConfig(options.provider, options.model);
      if (!llmConfig) {
        console.error("Error: --ai requires an API key.");
        if (tempDir) rmSync(tempDir, { recursive: true, force: true });
        process.exit(1);
      }
      console.error(`🤖 Running AI analysis...`);
      
      const files = collectFiles(scanDir);
      const llmFindings = await runLlmAnalysis(files, llmConfig);
      result.findings.push(...llmFindings);
      const { computeScore, computeScoreV2 } = await import("./score.js");
      const { totalLines } = await import("./scanner/files.js");
      result.score = computeScore(result.findings);
      const projectMeta2 = { fileList: files.map(f => f.relativePath), totalLines: totalLines(files), totalFiles: files.length, hasNetworkCalls: result.findings.some(f => !f.possibleFalsePositive && ["data-exfil","phone-home","network-ssrf"].includes(f.rule)) };
      result.scoreResult = computeScoreV2(result.findings, projectMeta2);
    }

    if (options.json) {
      printJsonReport(result);
    } else {
      printReport(result, { showScore: (options as any).score, lang: (options as any).lang || "zh" });
      // Install recommendation
      console.log();
      if (result.score >= 90) {
        console.log("✅ Safe to install — no significant risks detected.");
      } else if (result.score >= 75) {
        console.log("🟢 Low risk — minor issues detected, review before installing.");
      } else if (result.score >= 50) {
        console.log("⚠️ Elevated risk — investigate findings carefully before using.");
      } else if (result.score >= 25) {
        console.log("🔶 High risk — significant security issues detected. Not recommended.");
      } else if (result.score >= 0) {
        console.log("🔴 Critical risk — DO NOT install. Serious security issues detected.");
      } else {
        console.log("☠️ Severe risk — extremely dangerous. DO NOT use under any circumstances.");
      }
    }

    if (tempDir) rmSync(tempDir, { recursive: true, force: true });

    if (options.failUnder !== undefined && result.score < options.failUnder) {
      process.exit(1);
    }
  });

program
  .command("discover")
  .description("Discover installed AI agents, MCP servers, and skills on this machine")
  .option("--json", "Output as JSON")
  .option("--scan", "Auto-scan all discovered config and skill directories")
  .action((options: { json?: boolean; scan?: boolean }) => {
    const agents = discoverAgents();
    if (options.json) {
      console.log(JSON.stringify({ agents, totalAgents: agents.length, totalMcpServers: agents.reduce((s, a) => s + (a.mcpServerCount || 0), 0) }, null, 2));
    } else {
      printDiscovery(agents);
    }
    if (options.scan && agents.length > 0) {
      console.log("\n🔍 Scanning discovered configurations...\n");
      for (const agent of agents) {
        const paths: string[] = [];
        if (agent.configPath) paths.push(agent.configPath);
        if (agent.skillsDir) paths.push(agent.skillsDir);
        for (const p of paths) {
          if (existsSync(p) && statSync(p).isDirectory()) {
            console.log(`\n📁 ${agent.name}: ${p}`);
            const result = scan(p);
            printReport(result, { showScore: (options as any).score, lang: (options as any).lang || "zh" });
          }
        }
      }
    }
  });

// Runtime MCP proxy
program
  .command("proxy")
  .description("Run as a security proxy between MCP client and server")
  .argument("<command>", "MCP server command to proxy")
  .argument("[args...]", "Arguments for the server command")
  .option("--enforce", "Block high-risk tool calls (default: monitor only)")
  .option("--rate-limit <n>", "Max tool calls per minute", parseInt)
  .option("--log <file>", "Write alerts to JSONL file")
  .action(async (command: string, args: string[], options: { enforce?: boolean; rateLimit?: number; log?: string }) => {
    const { McpProxy } = await import("./runtime/proxy.js");

    const proxy = new McpProxy({
      serverCommand: command,
      serverArgs: args,
      enforce: options.enforce,
      rateLimit: options.rateLimit,
      logFile: options.log,
    });

    proxy.start();
  });

// MCP server audit
program
  .command("mcp-audit")
  .description("Audit an MCP server's registered tools for security issues")
  .argument("<command>", "MCP server command to audit")
  .argument("[args...]", "Arguments for the server command")
  .action(async (command: string, args: string[]) => {
    const { auditMcpServer } = await import("./runtime/proxy.js");

    console.log(`🛡️ Auditing MCP server: ${command} ${args.join(" ")}`);
    console.log();

    try {
      const { tools, alerts } = await auditMcpServer(command, args);
      console.log(`📋 Tools registered: ${tools}`);
      console.log(`🔍 Security alerts: ${alerts.length}`);
      console.log();

      if (alerts.length === 0) {
        console.log("✅ No security issues found in tool registrations.");
      } else {
        const high = alerts.filter(a => a.level === "high");
        const medium = alerts.filter(a => a.level === "medium");
        const low = alerts.filter(a => a.level === "low");

        if (high.length > 0) console.log(`🔴 High: ${high.length}`);
        if (medium.length > 0) console.log(`🟡 Medium: ${medium.length}`);
        if (low.length > 0) console.log(`🟢 Low: ${low.length}`);
        console.log();

        for (const alert of [...high, ...medium, ...low]) {
          const icon = alert.level === "high" ? "🔴" : alert.level === "medium" ? "🟡" : "🟢";
          console.log(`${icon} [${alert.rule}] ${alert.message}`);
          console.log(`   Tool: ${alert.toolName}`);
          console.log(`   ${alert.evidence.substring(0, 120)}`);
          console.log();
        }
      }
    } catch (e: any) {
      console.error(`❌ Audit failed: ${e.message}`);
      process.exit(1);
    }
  });

// ─── Provenance commands ───

program
  .command("provenance")
  .description("Generate a content hash manifest for provenance tracking")
  .argument("<directory>", "Target directory")
  .option("--name <name>", "Skill/plugin name")
  .option("--tag <tag>", "Version tag string", "0.0.0")
  .action((directory: string, options: { name?: string; tag?: string }) => {
    const target = resolve(directory);
    if (!existsSync(target)) { console.error(`Error: "${directory}" not found`); process.exit(1); }

    
    const files = collectFiles(target);
    const result = scan(target);
    const grade = result.scoreResult?.grade ?? letterGrade(result.score);

    const manifest = generateManifest(
      options.name || basename(target),
      options.tag || "0.0.0",
      files,
      grade,
      result.score,
    );

    const path = saveManifest(target, manifest);
    console.log(`✅ Manifest saved to ${path}`);
    console.log(`   Content hash: ${manifest.contentHash}`);
    console.log(`   Files: ${Object.keys(manifest.files).length}`);
    console.log(`   Grade: ${grade} (${result.score})`);
  });

program
  .command("verify")
  .description("Verify files against saved provenance manifest")
  .argument("<directory>", "Target directory")
  .action((directory: string) => {
    const target = resolve(directory);
    const manifest = loadManifest(target);
    if (!manifest) {
      console.error("❌ No manifest found. Run `agent-shield provenance <dir>` first.");
      process.exit(1);
    }

    
    const files = collectFiles(target);
    const verification = verifyManifest(files, manifest);

    if (verification.valid) {
      console.log(`✅ Provenance verified — content matches manifest`);
      console.log(`   Hash: ${manifest.contentHash}`);
      console.log(`   Created: ${manifest.createdAt}`);
      console.log(`   Grade at creation: ${manifest.grade} (${manifest.score})`);
    } else {
      console.log(`⚠️  Content has changed since manifest was created`);
      if (verification.changed.length) {
        console.log(`\n   Modified files (${verification.changed.length}):`);
        verification.changed.forEach((f) => console.log(`     📝 ${f}`));
      }
      if (verification.added.length) {
        console.log(`\n   New files (${verification.added.length}):`);
        verification.added.forEach((f) => console.log(`     ➕ ${f}`));
      }
      if (verification.removed.length) {
        console.log(`\n   Removed files (${verification.removed.length}):`);
        verification.removed.forEach((f) => console.log(`     ➖ ${f}`));
      }
      console.log(`\n   Run \`agent-shield provenance ${directory}\` to update the manifest.`);

      // Re-scan and compare grades
      const result = scan(target);
      const currentGrade = result.scoreResult?.grade ?? letterGrade(result.score);
      if (manifest.grade && currentGrade !== manifest.grade) {
        console.log(`\n   ⚠️  Grade changed: ${manifest.grade} → ${currentGrade}`);
      }
      process.exit(1);
    }
  });

// ─── Policy command ───

program
  .command("policy")
  .description("Evaluate scan against per-agent security policy")
  .argument("<directory>", "Target directory")
  .argument("<agent>", "Agent name (from .agent-shield.yml agents section)")
  .option("--preset <preset>", "Use preset policy: strict | standard | permissive")
  .action((directory: string, agent: string, options: { preset?: string }) => {
    const target = resolve(directory);
    if (!existsSync(target)) { console.error(`Error: "${directory}" not found`); process.exit(1); }

    const result = scan(target);
    const config = loadConfig(target);

    let policy = getAgentPolicy(config, agent);
    if (!policy && options.preset) {
      policy = POLICY_PRESETS[options.preset] ?? null;
    }
    if (!policy) {
      console.error(`❌ No policy found for agent "${agent}". Define it in .agent-shield.yml or use --preset.`);
      console.error(`   Available presets: strict, standard, permissive`);
      process.exit(1);
    }

    const grade = result.scoreResult?.grade ?? letterGrade(result.score);
    console.log(`🛡️  Policy evaluation for agent "${agent}"`);
    console.log(`   Score: ${result.score} (${grade})`);
    console.log(`   Policy: minGrade=${policy.minGrade}${policy.minScore ? ` minScore=${policy.minScore}` : ""}${policy.maxSeverity ? ` maxSeverity=${policy.maxSeverity}` : ""}`);
    if (policy.blockRules?.length) console.log(`   Blocked rules: ${policy.blockRules.join(", ")}`);
    console.log();

    const evaluation = evaluatePolicy(result, policy);
    if (evaluation.pass) {
      console.log(`✅ PASS — this skill meets the security requirements for "${agent}"`);
    } else {
      console.log(`🚫 FAIL — this skill does NOT meet the security requirements:`);
      evaluation.reasons.forEach((r) => console.log(`   ❌ ${r}`));
      process.exit(1);
    }
  });

// Default: if first arg looks like a directory, treat as scan
const args = process.argv.slice(2);
if (args.length > 0 && !args[0]!.startsWith("-") && !["scan", "init", "watch", "compare", "badge", "discover", "install-check", "proxy", "mcp-audit", "provenance", "verify", "policy", "help"].includes(args[0]!)) {
  process.argv.splice(2, 0, "scan");
}

program.parse();
