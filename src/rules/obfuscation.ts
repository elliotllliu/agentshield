import type { Rule, Finding, ScannedFile } from "../types.js";

/**
 * Rule: obfuscation
 * Detects base64 decoding + eval/exec combos and other obfuscation patterns.
 */

const OBFUSCATION_PATTERNS: Array<{
  pattern: RegExp;
  desc: string;
  severity: "high" | "medium";
}> = [
  { pattern: /atob\s*\(.*\beval\b|eval\s*\(.*\batob\b/, desc: "atob() + eval() combo", severity: "high" },
  { pattern: /Buffer\.from\s*\([^)]*,\s*["']base64["']\).*\beval\b/, desc: "Base64 decode + eval()", severity: "high" },
  { pattern: /Buffer\.from\s*\([^)]*,\s*["']base64["']\).*\bexec\b/, desc: "Base64 decode + exec()", severity: "high" },
  // String.fromCharCode: only flag when chained (>3 calls) or combined with eval/Function
  // Single calls like String.fromCharCode(65 + n%26) are normal (e.g., Excel column names)
  { pattern: /\bString\.fromCharCode\s*\((?:[^)]*,\s*){3,}/, desc: "String.fromCharCode() with many args — potential obfuscation", severity: "medium" },
  { pattern: /(?:eval|Function)\s*\(.*\bString\.fromCharCode|String\.fromCharCode.*(?:eval|Function)\s*\(/, desc: "String.fromCharCode + eval/Function combo", severity: "high" },
  { pattern: /\\x[0-9a-f]{2}\\x[0-9a-f]{2}\\x[0-9a-f]{2}/, desc: "Hex-encoded string sequence", severity: "medium" },
  { pattern: /\\u00[0-9a-f]{2}\\u00[0-9a-f]{2}/, desc: "Unicode-escaped string sequence", severity: "medium" },
];

export const obfuscationRule: Rule = {
  id: "obfuscation",
  name: "Code Obfuscation",
  description: "Detects base64+eval combos, hex encoding, and other obfuscation techniques",

  run(files: ScannedFile[]): Finding[] {
    const findings: Finding[] = [];

    for (const file of files) {
      if (file.ext === ".json" || file.ext === ".yaml" || file.ext === ".yml" || file.ext === ".md") continue;

      // Check multi-line patterns across entire content
      for (const { pattern, desc, severity } of OBFUSCATION_PATTERNS.slice(0, 3)) {
        if (pattern.test(file.content)) {
          // Find the line with eval/exec
          for (let i = 0; i < file.lines.length; i++) {
            if (/\beval\b|\bexec\b/.test(file.lines[i]!)) {
              findings.push({ rule: "obfuscation", severity, file: file.relativePath, line: i + 1, message: desc, evidence: file.lines[i]!.trim().slice(0, 120) });
              break;
            }
          }
        }
      }

      // Per-line patterns
      for (let i = 0; i < file.lines.length; i++) {
        const line = file.lines[i]!;
        const trimmed = line.trimStart();
        if (trimmed.startsWith("//") || trimmed.startsWith("#")) continue;

        for (const { pattern, desc, severity } of OBFUSCATION_PATTERNS.slice(3)) {
          if (pattern.test(line)) {
            findings.push({ rule: "obfuscation", severity, file: file.relativePath, line: i + 1, message: desc, evidence: line.trim().slice(0, 120) });
            break;
          }
        }
      }
    }

    return findings;
  },
};
