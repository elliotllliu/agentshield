import { loadConfig } from "../config.js";
import { dirname } from "path";
import type { Rule, Finding, ScannedFile } from "../types.js";

/**
 * Rule: phone-home
 * Detects periodic timers combined with HTTP requests — "calling home" patterns.
 */

const TIMER_RE = /setInterval\s*\(|cron\s*\(|schedule\s*\(|setTimeout.*setInterval|recurring|periodic/i;
const HTTP_RE = /fetch\s*\(|axios\.|http\.request|https\.request|\.post\s*\(|\.get\s*\(/i;

export const phoneHomeRule: Rule = {
  id: "phone-home",
  name: "Phone Home / Beacon",
  description: "Detects periodic timers combined with HTTP requests (heartbeat/beacon pattern)",

  run(files: ScannedFile[]): Finding[] {
    const findings: Finding[] = [];
    const config = loadConfig(dirname(files[0]?.filePath || process.cwd()));

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
      if (file.ext === ".json" || file.ext === ".yaml" || file.ext === ".yml" || file.ext === ".md") continue;

      const sdkConf = file.usesKnownSdk ? "low" as const : "high" as const;
      const hasTimer = TIMER_RE.test(file.content);
      const hasHttp = HTTP_RE.test(file.content);

      if (hasTimer && hasHttp) {
        // Find the timer line
        for (let i = 0; i < file.lines.length; i++) {
          const line = file.lines[i]!;
          if (TIMER_RE.test(line)) {
            // Check if the HTTP request is to a known safe API in the same line or nearby
            // This is a heuristic, a full AST would be better for precise linking
            if (HTTP_RE.test(line) && SAFE_API_REGEX.test(line)) {
              // Timer + HTTP to safe API, downgrade or skip
              // For now, skip to reduce FP on legitimate polling to known services
              continue;
            }

            findings.push({
              rule: "phone-home",
              severity: "medium",
              file: file.relativePath,
              line: i + 1,
              message: "Periodic timer + HTTP request — possible beacon/phone-home pattern",
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
