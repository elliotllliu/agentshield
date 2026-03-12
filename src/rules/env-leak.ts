import type { Rule, Finding, ScannedFile } from "../types.js";

/**
 * Rule: env-leak
 * Detects process.env access combined with HTTP send — leaking environment variables.
 */

const ENV_ACCESS_RE = /process\.env\b|os\.environ|getenv\s*\(/i;
const HTTP_SEND_RE = /fetch\s*\(|axios\.|http\.request|https\.request|requests\.(post|put|patch)|\.post\s*\(|curl\s/i;

export const envLeakRule: Rule = {
  id: "env-leak",
  name: "Environment Variable Leak",
  description: "Detects process.env access combined with outbound HTTP requests",

  run(files: ScannedFile[]): Finding[] {
    const findings: Finding[] = [];

    for (const file of files) {
      if (file.ext === ".json" || file.ext === ".yaml" || file.ext === ".yml" || file.ext === ".md") continue;

      const hasEnvAccess = ENV_ACCESS_RE.test(file.content);
      const hasHttpSend = HTTP_SEND_RE.test(file.content);

      if (hasEnvAccess && hasHttpSend) {
        const envLines: number[] = [];
        const sendLines: number[] = [];

        for (let i = 0; i < file.lines.length; i++) {
          const line = file.lines[i]!;
          if (ENV_ACCESS_RE.test(line)) envLines.push(i + 1);
          if (HTTP_SEND_RE.test(line)) sendLines.push(i + 1);
        }

        if (envLines.length > 0 && sendLines.length > 0) {
          findings.push({
            rule: "env-leak",
            severity: "critical",
            file: file.relativePath,
            line: sendLines[0],
            message: `Reads environment variables (line ${envLines.join(",")}) and sends HTTP request (line ${sendLines.join(",")}) — possible env leak`,
            evidence: file.lines[sendLines[0]! - 1]?.trim().slice(0, 120),
          });
        }
      }
    }

    return findings;
  },
};
