import { execSync } from "child_process";
import { existsSync } from "fs";
import { join } from "path";
import type { Rule, Finding, ScannedFile } from "../types.js";

/**
 * Rule: supply-chain
 * Runs npm audit to detect known CVEs in dependencies.
 */

export const supplyChainRule: Rule = {
  id: "supply-chain",
  name: "Supply Chain Audit",
  description: "Checks for known CVEs in npm/pip dependencies",

  run(files: ScannedFile[]): Finding[] {
    const findings: Finding[] = [];

    // Determine the target directory from the first file
    if (files.length === 0) return findings;

    const targetDir = files[0]!.filePath.replace(files[0]!.relativePath, "").replace(/\/$/, "");

    // Check for package.json
    const pkgJsonPath = join(targetDir, "package.json");
    const hasNodeModules = existsSync(join(targetDir, "node_modules"));
    const hasPkgJson = existsSync(pkgJsonPath);
    const hasLockFile =
      existsSync(join(targetDir, "package-lock.json")) ||
      existsSync(join(targetDir, "yarn.lock")) ||
      existsSync(join(targetDir, "pnpm-lock.yaml"));

    if (hasPkgJson && (hasNodeModules || hasLockFile)) {
      try {
        // npm audit returns exit code > 0 when vulnerabilities are found
        const result = execSync("npm audit --json 2>/dev/null", {
          cwd: targetDir,
          encoding: "utf-8",
          timeout: 30000,
          stdio: ["pipe", "pipe", "pipe"],
        });
        parseNpmAudit(result, findings);
      } catch (err: unknown) {
        // npm audit exits non-zero when vulns are found
        if (err && typeof err === "object" && "stdout" in err) {
          parseNpmAudit((err as { stdout: string }).stdout, findings);
        }
      }
    } else if (hasPkgJson) {
      // Has package.json but no lock file — check deps manually
      try {
        const pkgContent = files.find((f) => f.relativePath === "package.json");
        if (pkgContent) {
          const pkg = JSON.parse(pkgContent.content);
          const deps = { ...pkg.dependencies, ...pkg.devDependencies };
          const depCount = Object.keys(deps).length;
          if (depCount > 0) {
            findings.push({
              rule: "supply-chain",
              severity: "low",
              file: "package.json",
              message: `${depCount} dependencies declared — run 'npm install && npm audit' for full CVE check`,
              confidence: "medium",
            });
          }
        }
      } catch {
        // ignore parse errors
      }
    }

    // Check for requirements.txt (Python)
    const reqTxt = files.find(
      (f) => f.relativePath === "requirements.txt" || f.relativePath.endsWith("/requirements.txt"),
    );
    if (reqTxt) {
      findings.push({
        rule: "supply-chain",
        severity: "low",
        file: reqTxt.relativePath,
        message: "Python requirements.txt found — run 'pip-audit' for CVE check",
        confidence: "medium",
      });
    }

    return findings;
  },
};

function parseNpmAudit(output: string, findings: Finding[]): void {
  try {
    const audit = JSON.parse(output);

    if (audit.vulnerabilities) {
      for (const [name, vuln] of Object.entries<Record<string, unknown>>(audit.vulnerabilities)) {
        const severity = (vuln.severity as string) || "moderate";
        const via = Array.isArray(vuln.via) ? vuln.via : [];
        const cves = via
          .filter((v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && "url" in v)
          .map((v) => String(v.url))
          .join(", ");

        const mappedSeverity: "high" | "medium" | "low" =
          severity === "critical" || severity === "high" ? "high" :
          severity === "moderate" ? "medium" : "low";

        findings.push({
          rule: "supply-chain",
          severity: mappedSeverity,
          file: "package.json",
          message: `${name} — ${severity} severity${cves ? ` (${cves})` : ""}`,
          evidence: typeof vuln.range === "string" ? `affected: ${vuln.range}` : undefined,
          confidence: "medium",
        });
      }
    }
  } catch {
    // unparseable output
  }
}
