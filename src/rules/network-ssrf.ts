import { loadConfig } from "../config.js";
import { dirname } from "path";
import type { Rule, Finding, ScannedFile } from "../types.js";

/**
 * Rule: network-ssrf
 * Detects Server-Side Request Forgery patterns — user-controlled URLs in HTTP requests.
 */

const SSRF_PATTERNS: Array<{ pattern: RegExp; desc: string; severity: "medium" | "medium" }> = [
  // Template literals in fetch/request
  { pattern: /fetch\s*\(\s*`[^`]*\$\{/, desc: "fetch() with template literal URL — potential SSRF", severity: "medium" },
  { pattern: /axios\.\w+\s*\(\s*`[^`]*\$\{/, desc: "axios with template literal URL — potential SSRF", severity: "medium" },
  { pattern: /http\.request\s*\(\s*`[^`]*\$\{/, desc: "http.request with template literal URL — potential SSRF", severity: "medium" },
  // URL constructed from user input
  { pattern: /new\s+URL\s*\(\s*(?:req\.|request\.|params\.|query\.|body\.)/, desc: "URL from request parameters — potential SSRF", severity: "medium" },
  { pattern: /fetch\s*\(\s*(?:req\.|request\.|params\.|query\.|body\.)/, desc: "fetch() with request parameter — potential SSRF", severity: "medium" },
  // Redirect to user-controlled URL
  { pattern: /redirect\s*\(\s*(?:req\.|request\.|params\.|query\.)/, desc: "Open redirect — user-controlled redirect URL", severity: "medium" },
  // Internal network access patterns
  { pattern: /127\.0\.0\.1|0\.0\.0\.0|localhost.*fetch|fetch.*localhost/i, desc: "Request to localhost — verify if intentional", severity: "medium" },
  { pattern: /169\.254\.169\.254/, desc: "AWS metadata endpoint access — potential SSRF", severity: "medium" },
];

export const networkSsrfRule: Rule = {
  id: "network-ssrf",
  name: "Server-Side Request Forgery",
  description: "Detects user-controlled URLs in HTTP requests and internal network access",

  run(files: ScannedFile[]): Finding[] {
    const findings: Finding[] = [];
    const config = loadConfig(dirname(files[0]?.filePath || process.cwd()));

    // Combine default safe APIs with user-defined safe domains
    const defaultSafeApis = [
      "(?:feishu\\.cn|lark\\.com)",
      "github\\.com",
      "googleapis\\.com",
      "openai\\.com",
      "anthropic\\.com",
      "api\\.slack\\.com",
      "graph\\.microsoft\\.com",
      "api\\.twitter\\.com",
      "api\\.telegram\\.org",
      "discord\\.com",
      "api\\.stripe\\.com",
      "api\\.twilio\\.com",
      "api\\.sendgrid\\.com",
    ];
    const safeDomainRegexes = [...defaultSafeApis, ...(config.safeDomains || [])];
    const SAFE_API_REGEX = new RegExp(safeDomainRegexes.map(d => `(${d})`).join("|"), "i");

    for (const file of files) {
      if (file.ext === ".json" || file.ext === ".yaml" || file.ext === ".yml" || file.ext === ".md") continue;

      const sdkConf = file.usesKnownSdk ? "low" as const : "medium" as const;

      for (let i = 0; i < file.lines.length; i++) {
        const line = file.lines[i]!;
        const trimmed = line.trimStart();
        if (trimmed.startsWith("//") || trimmed.startsWith("#")) continue;

        for (const { pattern, desc, severity } of SSRF_PATTERNS) {
          if (pattern.test(line)) {
            // Skip template literal URLs to known safe API domains
            if (desc.includes("template literal") && SAFE_API_REGEX.test(line)) continue;

            findings.push({
              rule: "network-ssrf",
              severity,
              file: file.relativePath,
              line: i + 1,
              message: desc,
              evidence: line.trim().slice(0, 120),
              confidence: sdkConf,
            });
            break;
          }
        }
      }
    }

    return findings;
  },
};
