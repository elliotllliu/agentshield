import type { Rule, Finding, ScannedFile } from "../types.js";
import { analyzeAuthFlow } from "../analyzers/auth-flow.js";

/**
 * Rule: env-leak
 * Detects process.env access combined with HTTP send to UNKNOWN destinations.
 * Normal pattern: reading API keys from env to call known APIs is safe.
 * Suspicious pattern: reading env vars and sending to unknown/user-controlled URLs.
 */

const ENV_ACCESS_RE = /process\.env\b|os\.environ|getenv\s*\(/i;
const HTTP_SEND_RE = /fetch\s*\(|axios\.|http\.request|https\.request|requests\.(post|put|patch)|\.post\s*\(|curl\s/i;

// Known safe API endpoints — reading env to call these is normal (e.g., OAuth token exchange)
const SAFE_API_RE = /(?:feishu\.cn|lark\.com|github\.com|googleapis\.com|openai\.com|anthropic\.com|api\.slack\.com|graph\.microsoft\.com|api\.twitter\.com|api\.telegram\.org|discord\.com|api\.stripe\.com|api\.twilio\.com|api\.sendgrid\.com|api\.hubspot\.com|api\.notion\.com|api\.airtable\.com|login\.microsoftonline\.com|accounts\.google\.com|oauth)/i;

export const envLeakRule: Rule = {
  id: "env-leak",
  name: "Environment Variable Leak",
  description: "Detects process.env access combined with outbound HTTP requests to unknown destinations",

  run(files: ScannedFile[]): Finding[] {
    const findings: Finding[] = [];

    for (const file of files) {
      if (file.ext === ".json" || file.ext === ".yaml" || file.ext === ".yml" || file.ext === ".md") continue;

      const sdkConf = file.usesKnownSdk ? "low" as const : "medium" as const;
      const authResult = analyzeAuthFlow(file);
      const effectiveConf = authResult.hasAuthFlow ? "low" as const : sdkConf;

      const hasEnvAccess = ENV_ACCESS_RE.test(file.content);
      const hasHttpSend = HTTP_SEND_RE.test(file.content);

      if (hasEnvAccess && hasHttpSend) {
        const envLines: number[] = [];
        const sendLines: number[] = [];
        let allSendsSafe = true;

        for (let i = 0; i < file.lines.length; i++) {
          const line = file.lines[i]!;
          if (ENV_ACCESS_RE.test(line)) envLines.push(i + 1);
          if (HTTP_SEND_RE.test(line)) {
            sendLines.push(i + 1);
            // Check if this HTTP call goes to a known safe API
            if (!SAFE_API_RE.test(line)) {
              // Also check surrounding lines (URL might be on previous line)
              const prevLine = file.lines[i - 1] || "";
              const nextLine = file.lines[i + 1] || "";
              if (!SAFE_API_RE.test(prevLine) && !SAFE_API_RE.test(nextLine)) {
                allSendsSafe = false;
              }
            }
          }
        }

        // Only flag if HTTP sends go to unknown destinations
        if (envLines.length > 0 && sendLines.length > 0 && !allSendsSafe) {
          findings.push({
            rule: "env-leak",
            severity: "medium",
            file: file.relativePath,
            line: sendLines[0],
            message: `Reads environment variables (line ${envLines.join(",")}) and sends HTTP request (line ${sendLines.join(",")}) — possible env leak`,
            evidence: file.lines[sendLines[0]! - 1]?.trim().slice(0, 120),
            confidence: effectiveConf,
          });
        }
      }
    }

    return findings;
  },
};
