import type { Rule, Finding, ScannedFile } from "../types.js";

/**
 * Rule: crypto-mining
 * Detects cryptocurrency mining patterns.
 */

const MINING_PATTERNS: Array<{ pattern: RegExp; desc: string }> = [
  { pattern: /stratum\+tcp:\/\/|stratum\+ssl:\/\//, desc: "Stratum mining protocol URL" },
  { pattern: /xmrig|cpuminer|minerd|minergate|coinhive|cryptonight/i, desc: "Known mining software reference" },
  { pattern: /\bmining_pool\b|\bpool_url\b|\bpool_address\b/i, desc: "Mining pool configuration" },
  { pattern: /\bmonero\b.*\bwallet\b|\bwallet\b.*\bmonero\b/i, desc: "Monero wallet reference" },
  { pattern: /crypto\.createHash.*\bwhile\b.*true|for\s*\(\s*;\s*;\s*\).*hash/i, desc: "Infinite loop with hashing — potential mining" },
];

export const cryptoMiningRule: Rule = {
  id: "crypto-mining",
  name: "Cryptocurrency Mining",
  description: "Detects mining pool connections, known miners, and mining-related patterns",

  run(files: ScannedFile[]): Finding[] {
    const findings: Finding[] = [];

    for (const file of files) {
      if (file.ext === ".md") continue;

      for (let i = 0; i < file.lines.length; i++) {
        const line = file.lines[i]!;

        for (const { pattern, desc } of MINING_PATTERNS) {
          if (pattern.test(line)) {
            findings.push({
              rule: "crypto-mining",
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
    }

    return findings;
  },
};
