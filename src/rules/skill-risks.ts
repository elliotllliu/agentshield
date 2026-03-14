import type { Rule, Finding, ScannedFile } from "../types.js";

/**
 * Rule: skill-risks
 * Detects high-risk patterns in agent skills that may indicate
 * dangerous capabilities or insecure practices.
 *
 * Based on Snyk Agent Scan issue codes:
 * - W007: Insecure credential handling
 * - W009: Direct financial execution
 * - W011: Exposure to untrusted third-party content
 * - W012: Unverifiable external dependency (runtime fetch of instructions)
 * - W013: System service modification
 */

// W007: Insecure credential handling — skill asks agent to output secrets verbatim
const INSECURE_CRED_PATTERNS: Array<{ pattern: RegExp; description: string }> = [
  { pattern: /(?:paste|type|enter|input|write|include|put)\s+(?:your\s+)?(?:api\s+key|token|password|secret|credential|access\s+key)\s+(?:here|below|in\s+the|into|directly)/i, description: "Asks user to paste credentials directly" },
  { pattern: /(?:hardcode|embed|include|put)\s+(?:the\s+)?(?:api\s+key|token|password|secret)\s+(?:in|into|inside)\s+(?:the\s+)?(?:code|file|config|script)/i, description: "Instructs embedding secrets in code" },
  { pattern: /(?:api_key|token|password|secret)\s*[:=]\s*["'][A-Za-z0-9_\-]{20,}["']/i, description: "Appears to contain a hardcoded credential in instructions" },
];

// W009: Financial execution capabilities
const FINANCIAL_PATTERNS: Array<{ pattern: RegExp; description: string }> = [
  { pattern: /(?:send|transfer|move|wire)\s+(?:money|funds|payment|bitcoin|crypto|eth|btc|usdt)/i, description: "Direct money transfer capability" },
  { pattern: /(?:execute|place|submit)\s+(?:a\s+)?(?:trade|order|transaction|purchase|buy\s+order|sell\s+order)/i, description: "Financial trade/order execution" },
  { pattern: /(?:stripe|paypal|braintree|square)\.(?:charges?|payments?)\.create/i, description: "Payment processing API call" },
  { pattern: /(?:web3|ethers|solana).*(?:sendTransaction|transfer|sign)/i, description: "Blockchain transaction execution" },
];

// W011: Untrusted content exposure
const UNTRUSTED_CONTENT_PATTERNS: Array<{ pattern: RegExp; description: string }> = [
  { pattern: /(?:browse|visit|open|navigate|fetch|scrape|crawl)\s+(?:any\s+)?(?:arbitrary|user[- ]?provided|unknown|untrusted)\s+(?:url|website|webpage|link|page)/i, description: "Browses arbitrary user-provided URLs" },
  { pattern: /(?:read|parse|analyze|process)\s+(?:social\s+media|forum|reddit|twitter|comments?|reviews?|posts?)\s+(?:from|on|at)/i, description: "Processes untrusted social media content" },
  { pattern: /(?:download|fetch|get|retrieve)\s+(?:content|data|text|html)\s+from\s+(?:any|arbitrary|user)/i, description: "Downloads content from arbitrary sources" },
];

// W012: Unverifiable external dependency — runtime code/instruction fetch
const EXTERNAL_DEP_PATTERNS: Array<{ pattern: RegExp; description: string }> = [
  { pattern: /(?:fetch|download|pull|get)\s+(?:the\s+)?(?:latest|updated?|current)\s+(?:instructions?|prompts?|config|rules?|script)\s+from\s+/i, description: "Fetches instructions from external URL at runtime" },
  { pattern: /(?:auto[- ]?update|self[- ]?update|live[- ]?reload)\s+(?:from|via|using)\s+/i, description: "Auto-update mechanism from external source" },
  { pattern: /(?:eval|exec|execute|run)\s*\(\s*(?:await\s+)?(?:fetch|axios|got|request)\s*\(/i, description: "Fetches and executes remote code" },
  { pattern: /(?:import|require|load)\s*\(\s*(?:['"`]https?:\/\/|url|endpoint)/i, description: "Dynamic import from remote URL" },
];

// W013: System service modification
const SYSTEM_MOD_PATTERNS: Array<{ pattern: RegExp; description: string }> = [
  { pattern: /(?:sudo|doas|runas)\s+/i, description: "Elevated privilege execution" },
  { pattern: /(?:systemctl|service|launchctl|sc\.exe)\s+(?:start|stop|enable|disable|restart|create)/i, description: "System service management" },
  { pattern: /(?:crontab|schtasks|at\s+\d|launchd)\s+/i, description: "Scheduled task creation" },
  { pattern: /(?:chmod\s+[0-7]*[1-7][0-7]*|chown\s+root|setuid|setgid)/i, description: "Permission/ownership modification" },
  { pattern: /(?:\/etc\/(?:passwd|shadow|sudoers|crontab|hosts|resolv|fstab|profile|rc\.local))/i, description: "Modifies critical system configuration files" },
  { pattern: /(?:iptables|ufw|firewalld|netsh\s+firewall)\s+/i, description: "Firewall rule modification" },
  { pattern: /(?:~\/\.bashrc|~\/\.zshrc|~\/\.profile|~\/\.bash_profile|\/etc\/environment)\b/i, description: "Shell profile/environment modification" },
];

export const skillRisks: Rule = {
  id: "skill-risks",
  name: "Skill Risk Assessment",
  description: "Detects high-risk capabilities in skills: financial ops, untrusted content, external deps, system modification",

  run(files: ScannedFile[]): Finding[] {
    const findings: Finding[] = [];

    for (const file of files) {
      const isSkillMd = file.relativePath.toLowerCase().includes("skill.md");
      const isMarkdown = file.ext === ".md";
      const isCode = [".ts", ".js", ".py", ".sh", ".bash"].includes(file.ext);
      const isConfig = [".json", ".yaml", ".yml"].includes(file.ext);

      if (!isMarkdown && !isCode && !isConfig) continue;

      for (let i = 0; i < file.lines.length; i++) {
        const line = file.lines[i]!;
        const trimmed = line.trimStart();
        if (trimmed.startsWith("//") || trimmed.startsWith("#") && !trimmed.startsWith("#!")) continue;

        // W007: Insecure credential handling (in markdown/docs)
        if (isMarkdown) {
          for (const { pattern, description } of INSECURE_CRED_PATTERNS) {
            if (pattern.test(line)) {
              findings.push({
                rule: "skill-risks",
                severity: "medium",
                file: file.relativePath,
                line: i + 1,
                message: `Insecure credential handling: ${description}`,
                evidence: line.trim().substring(0, 120),
                confidence: "low",
              });
              break;
            }
          }
        }

        // W009: Financial execution
        for (const { pattern, description } of FINANCIAL_PATTERNS) {
          if (pattern.test(line)) {
            findings.push({
              rule: "skill-risks",
              severity: "medium",
              file: file.relativePath,
              line: i + 1,
              message: `Financial execution: ${description}`,
              evidence: line.trim().substring(0, 120),
              confidence: "low",
            });
            break;
          }
        }

        // W011: Untrusted content (primarily in SKILL.md)
        if (isSkillMd || isMarkdown) {
          for (const { pattern, description } of UNTRUSTED_CONTENT_PATTERNS) {
            if (pattern.test(line)) {
              findings.push({
                rule: "skill-risks",
                severity: "medium",
                file: file.relativePath,
                line: i + 1,
                message: `Untrusted content exposure: ${description}`,
                evidence: line.trim().substring(0, 120),
                confidence: "low",
              });
              break;
            }
          }
        }

        // W012: External dependency
        if (isCode || isMarkdown) {
          for (const { pattern, description } of EXTERNAL_DEP_PATTERNS) {
            if (pattern.test(line)) {
              findings.push({
                rule: "skill-risks",
                severity: isCode ? "medium" : "medium",
                file: file.relativePath,
                line: i + 1,
                message: `Unverifiable external dependency: ${description}`,
                evidence: line.trim().substring(0, 120),
                confidence: "low",
              });
              break;
            }
          }
        }

        // W013: System modification
        for (const { pattern, description } of SYSTEM_MOD_PATTERNS) {
          if (pattern.test(line)) {
            findings.push({
              rule: "skill-risks",
              severity: isSkillMd ? "medium" : "low",
              file: file.relativePath,
              line: i + 1,
              message: `System modification: ${description}`,
              evidence: line.trim().substring(0, 120),
              confidence: "low",
            });
            break;
          }
        }
      }
    }

    return findings;
  },
};
