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

    for (const file of files) {
      if (file.ext === ".json" || file.ext === ".yaml" || file.ext === ".yml" || file.ext === ".md") continue;

      const hasTimer = TIMER_RE.test(file.content);
      const hasHttp = HTTP_RE.test(file.content);

      if (hasTimer && hasHttp) {
        // Find the timer line
        for (let i = 0; i < file.lines.length; i++) {
          if (TIMER_RE.test(file.lines[i]!)) {
            findings.push({
              rule: "phone-home",
              severity: "warning",
              file: file.relativePath,
              line: i + 1,
              message: "Periodic timer + HTTP request — possible beacon/phone-home pattern",
              evidence: file.lines[i]!.trim().slice(0, 120),
            });
            break;
          }
        }
      }
    }

    return findings;
  },
};
