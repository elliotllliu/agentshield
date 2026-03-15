import { execSync } from "child_process";
import type { EngineAdapter, EngineResult, EngineFinding } from "./types.js";

export class SemgrepAdapter implements EngineAdapter {
  id = "semgrep";
  displayName = "Semgrep";
  focus = "General SAST: injection, XSS, SSRF, hardcoded secrets, insecure defaults (2000+ community rules)";
  url = "https://github.com/semgrep/semgrep";

  async isAvailable(): Promise<boolean> {
    try {
      execSync("semgrep --version 2>/dev/null", {
        timeout: 10000, stdio: "pipe", shell: "/bin/bash",
        env: { ...process.env, PATH: `${process.env.HOME}/.local/bin:${process.env.PATH}` },
      });
      return true;
    } catch {
      return false;
    }
  }

  installInstructions(): string {
    return `pipx install semgrep`;
  }

  async scan(targetDir: string): Promise<EngineResult> {
    const start = Date.now();
    const available = await this.isAvailable();
    if (!available) {
      return {
        engine: this.id, displayName: this.displayName, available: false, findings: null,
        error: `Not installed. Run: ${this.installInstructions()}`,
        durationMs: Date.now() - start, focus: this.focus,
      };
    }

    try {
      let raw: string;
      try {
        // Use auto config for community rules, JSON output, quiet mode
        raw = execSync(
          `semgrep scan "${targetDir}" --config p/default --json --quiet --no-git-ignore --timeout 30 --timeout-threshold 3 2>&1`,
          {
            timeout: 180000, stdio: ["pipe", "pipe", "pipe"], maxBuffer: 50 * 1024 * 1024,
            shell: "/bin/bash",
            env: {
              ...process.env,
              PATH: `${process.env.HOME}/.local/bin:${process.env.PATH}`,
              SEMGREP_SEND_METRICS: "off",
            },
          },
        ).toString();
      } catch (err: any) {
        // semgrep exits non-zero when findings exist
        raw = err.stdout?.toString() || "";
        if (!raw) throw err;
      }

      // Extract JSON (semgrep may prepend warnings)
      const jsonStart = raw.indexOf("{");
      if (jsonStart === -1) throw new Error("No JSON in semgrep output");
      const data = JSON.parse(raw.slice(jsonStart));
      const findings: EngineFinding[] = (data.results || []).map((r: any) => ({
        engine: this.id,
        severity: mapSeverity(r.extra?.severity || r.severity),
        file: r.path || "",
        line: r.start?.line || r.line,
        rule: r.check_id || r.rule_id || "",
        message: r.extra?.message || r.message || "",
        evidence: r.extra?.lines || "",
        confidence: mapConfidence(r.extra?.metadata?.confidence),
        category: r.extra?.metadata?.category || extractCategory(r.check_id || ""),
      }));

      return {
        engine: this.id, displayName: this.displayName,
        version: data.version, available: true, findings,
        durationMs: Date.now() - start, focus: this.focus,
      };
    } catch (err) {
      return {
        engine: this.id, displayName: this.displayName, available: true, findings: null,
        error: (err as Error).message?.slice(0, 200),
        durationMs: Date.now() - start, focus: this.focus,
      };
    }
  }
}

function mapSeverity(s: string): "high" | "medium" | "low" | "info" {
  const lower = (s || "").toLowerCase();
  if (lower === "error" || lower === "high" || lower === "critical") return "high";
  if (lower === "warning" || lower === "medium") return "medium";
  if (lower === "low" || lower === "info") return "low";
  return "info";
}

function mapConfidence(c: string | undefined): number {
  if (!c) return 0.6;
  const lower = c.toLowerCase();
  if (lower === "high") return 0.9;
  if (lower === "medium") return 0.6;
  return 0.3;
}

function extractCategory(checkId: string): string {
  // e.g., "javascript.express.security.audit.xss" → "security"
  const parts = checkId.split(".");
  return parts.find(p => ["security", "audit", "correctness", "performance"].includes(p)) || parts[2] || "";
}
