import type { Rule, Finding, ScannedFile } from "../types.js";

/**
 * Rule: credential-hardcode
 * Detects hardcoded API keys, tokens, and passwords in source code.
 */

const CREDENTIAL_PATTERNS: Array<{ pattern: RegExp; desc: string }> = [
  // Generic API keys / tokens
  { pattern: /["'](?:sk|pk|api[_-]?key|token|secret)[_-]?[a-zA-Z]*["']\s*[:=]\s*["'][a-zA-Z0-9_\-/.]{20,}["']/, desc: "Hardcoded API key/token" },
  // AWS
  { pattern: /AKIA[0-9A-Z]{16}/, desc: "Hardcoded AWS Access Key ID" },
  // GitHub
  { pattern: /ghp_[a-zA-Z0-9]{36}/, desc: "Hardcoded GitHub personal access token" },
  { pattern: /github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}/, desc: "Hardcoded GitHub fine-grained token" },
  // Slack
  { pattern: /xoxb-[0-9]{10,}-[0-9]{10,}-[a-zA-Z0-9]{24}/, desc: "Hardcoded Slack bot token" },
  { pattern: /xoxp-[0-9]{10,}-[0-9]{10,}-[0-9]{10,}-[a-f0-9]{32}/, desc: "Hardcoded Slack user token" },
  // OpenAI
  { pattern: /sk-[a-zA-Z0-9]{20,}T3BlbkFJ[a-zA-Z0-9]{20,}/, desc: "Hardcoded OpenAI API key" },
  // Stripe
  { pattern: /sk_live_[a-zA-Z0-9]{24,}/, desc: "Hardcoded Stripe live key" },
  // Generic password assignment
  { pattern: /(?:password|passwd|pwd)\s*[:=]\s*["'][^"']{8,}["']/i, desc: "Hardcoded password" },
  // Private key block
  { pattern: /-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----/, desc: "Embedded private key" },
];

export const credentialHardcodeRule: Rule = {
  id: "credential-hardcode",
  name: "Hardcoded Credentials",
  description: "Detects API keys, tokens, passwords, and private keys in source code",

  run(files: ScannedFile[]): Finding[] {
    const findings: Finding[] = [];

    for (const file of files) {
      if (file.ext === ".md") continue;

      for (let i = 0; i < file.lines.length; i++) {
        const line = file.lines[i]!;
        const trimmed = line.trimStart();
        if (trimmed.startsWith("//") || trimmed.startsWith("#") || trimmed.startsWith("*")) continue;

        for (const { pattern, desc } of CREDENTIAL_PATTERNS) {
          if (pattern.test(line)) {
            findings.push({
              rule: "credential-hardcode",
              severity: "high",
              file: file.relativePath,
              line: i + 1,
              message: desc,
              evidence: line.trim().replace(/["'][a-zA-Z0-9_\-/.]{10,}["']/g, '"***"').slice(0, 120),
              confidence: "medium",
            });
            break;
          }
        }
      }
    }

    return findings;
  },
};
