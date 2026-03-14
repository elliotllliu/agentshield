import { loadConfig } from "../config.js";
import { dirname } from "path";
import type { Rule, Finding, ScannedFile } from "../types.js";
import { analyzeAuthFlow } from "../analyzers/auth-flow.js";
import { analyzeDataFlow } from "../analyzers/data-flow.js";

/**
 * Rule: data-exfil
 * Detects code that reads sensitive files AND sends HTTP requests — a classic exfiltration pattern.
 */

const SENSITIVE_READ_RE =
  /readFile|readFileSync|fs\.read|\/\.ssh\/|\/\.aws\/|\/\.kube\/|\/\.npmrc|\/\.gitconfig/i;

/** Patterns that look like sensitive reads but aren't */
const SENSITIVE_FALSE_POSITIVE_RE =
  /SSHException|SSHClient|ssh_exception|load_dotenv|dotenv|\.env\.example|\.env\.template|metadata\.openclaw/i;

/** Credential access patterns that are NORMAL in plugin/SDK context */
const SAFE_CREDENTIAL_RE =
  /self\.runtime\.credentials|this\.credentials|self\.config|tool_parameters|plugin_config|runtime\.credentials|provider_credentials/i;

const HTTP_SEND_RE =
  /fetch\s*\(|axios\.|http\.request|https\.request|XMLHttpRequest|\.post\s*\(|\.put\s*\(|urllib|requests\.(post|put|patch)|curl\s/i;

const DYNAMIC_URL_RE =
  /fetch\s*\(\s*`[^`]*\$\{|fetch\s*\(\s*[a-zA-Z_]\w*\s*[+,)]/;

export const dataExfilRule: Rule = {
  id: "data-exfil",
  name: "Data Exfiltration",
  description: "Detects patterns where sensitive data is read and sent over HTTP",

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
    ];
    const safeDomainRegexes = [...defaultSafeApis, ...(config.safeDomains || [])];
    const SAFE_API_REGEX = new RegExp(safeDomainRegexes.map(d => `(${d})`).join("|"), "i");

    for (const file of files) {
      if (file.ext === ".json" || file.ext === ".yaml" || file.ext === ".yml" || file.ext === ".toml" || file.ext === ".md") continue;

      // SDK-aware confidence: if file uses known SDKs, lower confidence for network findings
      const sdkConf = file.usesKnownSdk ? "low" as const : "high" as const;

      // Auth flow detection: if file contains legitimate auth patterns, lower confidence
      const authResult = analyzeAuthFlow(file);
      const effectiveConf = authResult.hasAuthFlow
        ? "low" as const
        : sdkConf;

      // Data flow analysis: track variable flows from sources to sinks
      const dataFlow = analyzeDataFlow(file);
      // If all data flows go to safe APIs, lower confidence further
      const flowConf = dataFlow.sinkIsSafe && dataFlow.connections.length > 0
        ? "low" as const
        : effectiveConf;

      const content = file.content;
      const hasSensitiveRead = SENSITIVE_READ_RE.test(content);
      const hasHttpSend = HTTP_SEND_RE.test(content);

      // Critical: same file reads sensitive data AND sends it out
      if (hasSensitiveRead && hasHttpSend) {
        // Check if "sensitive reads" are actually safe credential access (plugin SDK patterns)
        const hasSafeCredentials = SAFE_CREDENTIAL_RE.test(content);
        
        // Find the specific lines
        const readLines: number[] = [];
        const sendLines: number[] = [];

        for (let i = 0; i < file.lines.length; i++) {
          const line = file.lines[i]!;
          // Skip lines that are safe credential access or false positive patterns
          if (SENSITIVE_READ_RE.test(line) && !SAFE_CREDENTIAL_RE.test(line) && !SENSITIVE_FALSE_POSITIVE_RE.test(line)) readLines.push(i + 1);
          if (HTTP_SEND_RE.test(line)) sendLines.push(i + 1);
        }

        if (readLines.length > 0 && sendLines.length > 0) {
          // Check if the HTTP request is to a known safe API
          const httpSendLine = file.lines[sendLines[0]! - 1];
          if (httpSendLine && SAFE_API_REGEX.test(httpSendLine)) {
            // It's a sensitive read + HTTP send, but to a safe API. Downgrade severity.
            findings.push({
              rule: "data-exfil",
              severity: "medium", // Downgraded from high
              file: file.relativePath,
              line: sendLines[0],
              message: `Reads sensitive data (line ${readLines.join(",")}) and sends HTTP request to known safe API (line ${sendLines.join(",")}) — possible exfiltration, but to safe domain. Review required.`,
              evidence: httpSendLine.trim().slice(0, 120),
              confidence: flowConf,
            });
          } else {
            findings.push({
              rule: "data-exfil",
              severity: "high",
              file: file.relativePath,
              line: sendLines[0],
              message: `Reads sensitive data (line ${readLines.join(",")}) and sends HTTP request (line ${sendLines.join(",")}) — possible exfiltration`,
              evidence: httpSendLine?.trim().slice(0, 120),
              confidence: flowConf,
            });
          }
        } else if (hasSafeCredentials && sendLines.length > 0) {
          // Credential access + HTTP is normal for API plugins — skip entirely
          // This block now accounts for SAFE_API_REGEX as part of the skip logic
          const httpSendLine = file.lines[sendLines[0]! - 1];
          if (httpSendLine && SAFE_API_REGEX.test(httpSendLine)) {
            continue; // Skip if safe credential access and to a safe API
          } else {
            // It's safe credential access, but to an unknown API. Could still be suspicious.
            // Downgrade to medium for review.
            findings.push({
              rule: "data-exfil",
              severity: "medium",
              file: file.relativePath,
              line: sendLines[0],
              message: `Reads credentials via safe access (line ${readLines.join(",")}) and sends HTTP request to unknown domain (line ${sendLines.join(",")}) — potential exfiltration`,
              evidence: httpSendLine?.trim().slice(0, 120),
              confidence: flowConf,
            });
          }
        }
      }

      // Warning: dynamic URL construction in fetch/request calls
      for (let i = 0; i < file.lines.length; i++) {
        const line = file.lines[i]!;
        if (DYNAMIC_URL_RE.test(line) && !SAFE_API_REGEX.test(line)) {
          findings.push({
            rule: "data-exfil",
            severity: "medium",
            file: file.relativePath,
            line: i + 1,
            message: "Dynamic URL construction in HTTP request — potential SSRF",
            evidence: line.trim().slice(0, 120),
            confidence: flowConf,
          });
        }
      }
    }

    return findings;
  },
};
