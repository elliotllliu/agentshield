import { Probot } from "probot";
import { execSync } from "child_process";
import { mkdtempSync, rmSync, writeFileSync, readFileSync, existsSync } from "fs";
import { join } from "path";
import { tmpdir } from "os";

interface AgentShieldConfig {
  failUnder?: number;
  disable?: string[];
  paths?: string[];
}

interface Finding {
  rule: string;
  severity: string;
  file: string;
  line?: number;
  message: string;
  evidence?: string;
  possibleFalsePositive?: boolean;
}

interface ScanResult {
  target: string;
  filesScanned: number;
  linesScanned: number;
  findings: Finding[];
  score: number;
  duration: number;
}

export = (app: Probot) => {
  app.on(["pull_request.opened", "pull_request.synchronize"], async (context) => {
    const { owner, repo } = context.repo();
    const pr = context.payload.pull_request;
    const sha = pr.head.sha;

    app.log.info(`Scanning PR #${pr.number} on ${owner}/${repo}`);

    // Load config from .agent-shield.yml in repo
    let config: AgentShieldConfig = { failUnder: 70 };
    try {
      const configFile = await context.octokit.repos.getContent({
        owner,
        repo,
        path: ".agent-shield.yml",
        ref: sha,
      });
      if ("content" in configFile.data) {
        const content = Buffer.from(configFile.data.content, "base64").toString();
        // Simple YAML parse for fail-under
        const failMatch = content.match(/failUnder:\s*(\d+)/);
        if (failMatch) config.failUnder = parseInt(failMatch[1]!);
      }
    } catch {
      // No config file, use defaults
    }

    // Create pending check
    await context.octokit.checks.create({
      owner,
      repo,
      name: "AgentShield Security Scan",
      head_sha: sha,
      status: "in_progress",
      output: {
        title: "Scanning...",
        summary: "AgentShield is analyzing your code for security issues.",
      },
    });

    // Clone repo and scan
    const tempDir = mkdtempSync(join(tmpdir(), "agent-shield-"));
    try {
      execSync(`git clone --depth 1 --branch ${pr.head.ref} https://github.com/${owner}/${repo}.git ${tempDir}/repo`, {
        stdio: "pipe",
        timeout: 60000,
      });

      // Run scan
      const scanPaths = config.paths || ["."];
      const results: ScanResult[] = [];

      for (const scanPath of scanPaths) {
        const fullPath = join(tempDir, "repo", scanPath);
        if (!existsSync(fullPath)) continue;

        try {
          const output = execSync(
            `npx -y @elliotllliu/agent-shield scan "${fullPath}" --json`,
            { stdio: "pipe", timeout: 120000, cwd: join(tempDir, "repo") }
          ).toString();
          results.push(JSON.parse(output));
        } catch (e: any) {
          if (e.stdout) {
            try { results.push(JSON.parse(e.stdout.toString())); } catch {}
          }
        }
      }

      // Aggregate results
      const totalScore = results.length > 0
        ? Math.round(results.reduce((sum, r) => sum + r.score, 0) / results.length)
        : 100;
      const allFindings = results.flatMap(r => r.findings).filter(f => !f.possibleFalsePositive);
      const high = allFindings.filter(f => f.severity === "high");
      const medium = allFindings.filter(f => f.severity === "medium");
      const low = allFindings.filter(f => f.severity === "low");

      // Build report
      const passed = totalScore >= (config.failUnder || 70);
      const scoreEmoji = totalScore >= 90 ? "✅" : totalScore >= 70 ? "🟡" : totalScore >= 40 ? "🟠" : "🔴";

      let body = `## 🛡️ AgentShield Security Scan\n\n`;
      body += `| Metric | Value |\n|--------|-------|\n`;
      body += `| Score | ${scoreEmoji} **${totalScore}/100** |\n`;
      body += `| 🔴 High | ${high.length} |\n`;
      body += `| 🟡 Medium | ${medium.length} |\n`;
      body += `| 🟢 Low | ${low.length} |\n`;
      body += `| Files | ${results.reduce((s, r) => s + r.filesScanned, 0)} |\n\n`;

      if (allFindings.length > 0) {
        body += `### Findings\n\n`;
        body += `| Severity | Location | Rule | Details |\n`;
        body += `|----------|----------|------|---------|\n`;
        for (const f of [...high, ...medium, ...low].slice(0, 25)) {
          const sev = f.severity === "high" ? "🔴" : f.severity === "medium" ? "🟡" : "🟢";
          const loc = f.line ? `\`${f.file}:${f.line}\`` : `\`${f.file}\``;
          body += `| ${sev} | ${loc} | \`${f.rule}\` | ${f.message} |\n`;
        }
        if (allFindings.length > 25) {
          body += `\n*... and ${allFindings.length - 25} more findings*\n`;
        }
        body += "\n";
      } else {
        body += "✅ **No security issues found!**\n\n";
      }

      body += `---\n*Powered by [AgentShield](https://github.com/elliotllliu/agent-shield) · 31 rules · Open source*`;

      // Post PR comment
      await context.octokit.issues.createComment({
        owner,
        repo,
        issue_number: pr.number,
        body,
      });

      // Update check
      await context.octokit.checks.create({
        owner,
        repo,
        name: "AgentShield Security Scan",
        head_sha: sha,
        status: "completed",
        conclusion: passed ? "success" : "failure",
        output: {
          title: passed
            ? `✅ Score: ${totalScore}/100`
            : `❌ Score: ${totalScore}/100 (below ${config.failUnder})`,
          summary: `Found ${high.length} high, ${medium.length} medium, ${low.length} low risk issues.`,
        },
      });

    } catch (error: any) {
      app.log.error(`Scan failed: ${error.message}`);
      await context.octokit.checks.create({
        owner,
        repo,
        name: "AgentShield Security Scan",
        head_sha: sha,
        status: "completed",
        conclusion: "failure",
        output: {
          title: "Scan failed",
          summary: `Error: ${error.message}`,
        },
      });
    } finally {
      rmSync(tempDir, { recursive: true, force: true });
    }
  });
};
