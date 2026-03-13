#!/usr/bin/env node
/**
 * toolhive-agentshield-integration.js
 * 
 * PoC: Integrate AgentShield security scanning into ToolHive's registry pipeline.
 * 
 * Usage:
 *   node toolhive-agentshield-integration.js [registry.json] [--fail-under 60]
 * 
 * This script:
 *   1. Reads a ToolHive registry JSON file
 *   2. Clones each MCP server's source repo
 *   3. Runs AgentShield scan on each
 *   4. Outputs per-server security scores + grade
 *   5. Optionally fails if any server scores below threshold
 * 
 * Integration points for ToolHive:
 *   - CI/CD: Run on registry PRs to gate new server additions
 *   - Registry Server: Add security_score field to server metadata
 *   - Portal UI: Display grade badge per server
 */

import { execSync } from "child_process";
import { readFileSync, mkdirSync, existsSync, writeFileSync } from "fs";
import { join } from "path";

const CACHE_DIR = "/tmp/toolhive-scan-cache";
const RESULTS_DIR = "/tmp/toolhive-scan-results";

function main() {
  const args = process.argv.slice(2);
  const registryPath = args.find(a => !a.startsWith("--")) || "registry.json";
  const failUnder = parseInt(args[args.indexOf("--fail-under") + 1]) || 0;

  console.log("╔══════════════════════════════════════════════════════════╗");
  console.log("║  ToolHive × AgentShield — Registry Security Scanner    ║");
  console.log("╚══════════════════════════════════════════════════════════╝\n");

  // Read registry
  const registry = JSON.parse(readFileSync(registryPath, "utf-8"));
  const servers = Object.entries(registry.servers);
  console.log(`📦 Registry: ${servers.length} servers\n`);

  mkdirSync(CACHE_DIR, { recursive: true });
  mkdirSync(RESULTS_DIR, { recursive: true });

  const results = [];

  for (const [name, info] of servers) {
    const repoUrl = info.repository_url;
    if (!repoUrl) {
      console.log(`⏭  ${name}: no repository_url, skipping`);
      continue;
    }

    const repoDir = join(CACHE_DIR, name);
    
    // Clone if not cached
    if (!existsSync(repoDir)) {
      try {
        execSync(`git clone --depth 1 --quiet "${repoUrl}" "${repoDir}"`, { stdio: "pipe" });
      } catch {
        console.log(`⚠️  ${name}: clone failed`);
        continue;
      }
    }

    // Run AgentShield scan
    try {
      const output = execSync(
        `npx @elliotllliu/agent-shield@0.7.0 scan "${repoDir}" --json`,
        { stdio: "pipe", maxBuffer: 10 * 1024 * 1024 }
      ).toString();
      
      const scan = JSON.parse(output);
      const score = Math.max(5, scan.score); // Clamp to v2 minimum
      const grade = score >= 90 ? "A" : score >= 75 ? "B" : score >= 60 ? "C" : score >= 40 ? "D" : "F";
      const high = scan.findings.filter(f => f.severity === "high").length;
      const med = scan.findings.filter(f => f.severity === "medium").length;
      
      const icon = grade === "A" ? "✅" : grade === "B" ? "🟡" : grade === "C" ? "🟠" : grade === "D" ? "🔴" : "⛔";
      console.log(`${icon} ${name}: ${score}/100 (${grade}) | High: ${high} | Med: ${med}`);
      
      // Save detailed result
      writeFileSync(join(RESULTS_DIR, `${name}.json`), JSON.stringify({
        server: name,
        repository: repoUrl,
        score,
        grade,
        findings: scan.findings,
        scannedFiles: scan.filesScanned,
        scannedLines: scan.linesScanned,
        scannedAt: new Date().toISOString(),
      }, null, 2));

      results.push({ name, score, grade, high, med, repoUrl });
    } catch (e) {
      console.log(`⚠️  ${name}: scan error`);
    }
  }

  // Summary
  console.log("\n" + "═".repeat(60));
  console.log(`\n📊 Results: ${results.length} servers scanned\n`);
  
  const gradeCount = { A: 0, B: 0, C: 0, D: 0, F: 0 };
  results.forEach(r => gradeCount[r.grade]++);
  
  console.log(`  ✅ A (Safe):     ${gradeCount.A}`);
  console.log(`  🟡 B (Caution):  ${gradeCount.B}`);
  console.log(`  🟠 C (Warning):  ${gradeCount.C}`);
  console.log(`  🔴 D (Danger):   ${gradeCount.D}`);
  console.log(`  ⛔ F (Critical): ${gradeCount.F}`);

  // Output for ToolHive registry enrichment
  const enrichment = {};
  results.forEach(r => {
    enrichment[r.name] = {
      security_score: r.score,
      security_grade: r.grade,
      high_findings: r.high,
      medium_findings: r.med,
      scanned_at: new Date().toISOString(),
      scanner: "agentshield@0.7.0",
    };
  });
  
  const enrichmentPath = join(RESULTS_DIR, "registry-enrichment.json");
  writeFileSync(enrichmentPath, JSON.stringify(enrichment, null, 2));
  console.log(`\n📁 Registry enrichment: ${enrichmentPath}`);
  console.log(`📁 Detailed reports: ${RESULTS_DIR}/`);

  // Fail check
  if (failUnder > 0) {
    const failed = results.filter(r => r.score < failUnder);
    if (failed.length > 0) {
      console.log(`\n❌ ${failed.length} server(s) below threshold (${failUnder}):`);
      failed.forEach(r => console.log(`   ${r.name}: ${r.score}/100`));
      process.exit(1);
    }
  }
}

main();
