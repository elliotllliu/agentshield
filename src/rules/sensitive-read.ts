import type { Rule, Finding, ScannedFile } from "../types.js";

/**
 * Rule: sensitive-read
 * Detects code that reads sensitive files like SSH keys, AWS credentials, etc.
 */

const SENSITIVE_PATTERNS: Array<{ pattern: RegExp; desc: string }> = [
  { pattern: /~\/\.ssh\/id_rsa|\.ssh\/id_rsa|ssh_key|id_ed25519/i, desc: "SSH private key" },
  { pattern: /~\/\.ssh\/known_hosts/i, desc: "SSH known_hosts" },
  { pattern: /~\/\.aws\/credentials|AWS_SECRET_ACCESS_KEY|aws_secret/i, desc: "AWS credentials" },
  { pattern: /~\/\.env\b|process\.env\b.*(?:SECRET|KEY|TOKEN|PASSWORD|CREDENTIAL)/i, desc: "environment secrets" },
  { pattern: /~\/\.openclaw\/openclaw\.json|openclaw\.json/i, desc: "OpenClaw config" },
  { pattern: /~\/\.gnupg|gpg.*private/i, desc: "GPG private key" },
  { pattern: /~\/\.kube\/config|kubeconfig/i, desc: "Kubernetes config" },
  { pattern: /\/etc\/shadow|\/etc\/passwd/i, desc: "system passwords" },
  { pattern: /~\/\.docker\/config\.json/i, desc: "Docker credentials" },
  { pattern: /~\/\.npmrc|_authToken/i, desc: "npm auth token" },
  { pattern: /~\/\.gitconfig|\.git-credentials/i, desc: "Git credentials" },
  { pattern: /~\/\.netrc/i, desc: "netrc credentials" },
];

export const sensitiveReadRule: Rule = {
  id: "sensitive-read",
  name: "Sensitive File Read",
  description: "Detects reads of SSH keys, credentials, API tokens, and other secrets",

  run(files: ScannedFile[]): Finding[] {
    const findings: Finding[] = [];

    for (const file of files) {
      // Skip non-code files (allow checking shell scripts, JS, TS, Python)
      if (file.ext === ".json" || file.ext === ".yaml" || file.ext === ".yml" || file.ext === ".toml") continue;
      if (file.relativePath === "SKILL.md") continue;

      for (let i = 0; i < file.lines.length; i++) {
        const line = file.lines[i]!;
        // Skip comments
        if (line.trimStart().startsWith("//") || line.trimStart().startsWith("#")) continue;

        for (const { pattern, desc } of SENSITIVE_PATTERNS) {
          if (pattern.test(line)) {
            findings.push({
              rule: "sensitive-read",
              severity: "low",
              file: file.relativePath,
              line: i + 1,
              message: `Accesses ${desc}`,
              evidence: line.trim().slice(0, 120),
              confidence: "medium",
            });
          }
        }
      }
    }

    return findings;
  },
};
