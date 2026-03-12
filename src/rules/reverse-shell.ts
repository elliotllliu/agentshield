import type { Rule, Finding, ScannedFile } from "../types.js";

/**
 * Rule: reverse-shell
 * Detects reverse shell patterns — outbound socket connections piped to shell.
 */

const REVERSE_SHELL_PATTERNS: Array<{ pattern: RegExp; desc: string }> = [
  // Shell
  { pattern: /\/dev\/tcp\/\d+\.\d+\.\d+\.\d+/, desc: "/dev/tcp reverse shell" },
  { pattern: /bash\s+-i\s+>&\s*\/dev\/tcp/, desc: "Bash interactive reverse shell" },
  { pattern: /nc\s+-e\s+\/bin\/(ba)?sh/, desc: "Netcat reverse shell" },
  { pattern: /ncat\s+.*-e\s+\/bin/, desc: "Ncat reverse shell" },
  { pattern: /mkfifo\s+.*\/tmp\/.*nc\s/, desc: "Named pipe + netcat reverse shell" },
  // Python
  { pattern: /socket\.connect\s*\(.*\bsubprocess\b|subprocess.*socket\.connect/i, desc: "Python socket + subprocess reverse shell" },
  { pattern: /pty\.spawn.*\/bin\/(ba)?sh/i, desc: "Python pty.spawn shell" },
  // Node.js
  { pattern: /net\.connect\s*\(.*child_process|child_process.*net\.connect/i, desc: "Node.js net.connect + child_process" },
  { pattern: /new\s+net\.Socket\s*\(\).*\.connect\s*\(.*\.pipe\s*\(/i, desc: "Node.js Socket pipe to process" },
];

export const reverseShellRule: Rule = {
  id: "reverse-shell",
  name: "Reverse Shell",
  description: "Detects outbound socket connections piped to a shell process",

  run(files: ScannedFile[]): Finding[] {
    const findings: Finding[] = [];

    for (const file of files) {
      if (file.ext === ".json" || file.ext === ".yaml" || file.ext === ".yml" || file.ext === ".md") continue;

      // Check both per-line and multi-line (for patterns spanning lines)
      for (let i = 0; i < file.lines.length; i++) {
        const line = file.lines[i]!;
        for (const { pattern, desc } of REVERSE_SHELL_PATTERNS) {
          if (pattern.test(line)) {
            findings.push({
              rule: "reverse-shell",
              severity: "critical",
              file: file.relativePath,
              line: i + 1,
              message: desc,
              evidence: line.trim().slice(0, 120),
            });
            break;
          }
        }
      }

      // Multi-line: check content for socket+subprocess combos
      if (REVERSE_SHELL_PATTERNS.some(({ pattern }) => pattern.test(file.content))) {
        // Already caught per-line
      }
    }

    return findings;
  },
};
