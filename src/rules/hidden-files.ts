import type { Rule, Finding, ScannedFile } from "../types.js";

/**
 * Rule: hidden-files
 * Detects exposed .env files and other hidden config files that shouldn't be committed.
 */

const DANGEROUS_FILES = [
  { pattern: /^\.env($|\.)/, desc: "Environment file with secrets" },
  { pattern: /^\.env\.local$/, desc: "Local environment file" },
  { pattern: /^\.env\.production$/, desc: "Production environment file" },
  { pattern: /^\.htpasswd$/, desc: "Apache password file" },
  { pattern: /^\.htaccess$/, desc: "Apache config file" },
  { pattern: /^\.pgpass$/, desc: "PostgreSQL password file" },
  { pattern: /^\.netrc$/, desc: "Network credentials file" },
];

const SECRET_IN_ENV_RE =
  /^[A-Z_]+=(?!$).*(?:key|secret|token|password|credential|auth)/i;

export const hiddenFilesRule: Rule = {
  id: "hidden-files",
  name: "Hidden/Secret Files",
  description: "Detects .env files and other hidden configs that may leak secrets",

  run(files: ScannedFile[]): Finding[] {
    const findings: Finding[] = [];

    for (const file of files) {
      const basename = file.relativePath.split("/").pop() || "";

      for (const { pattern, desc } of DANGEROUS_FILES) {
        if (pattern.test(basename)) {
          findings.push({
            rule: "hidden-files",
            severity: "critical",
            file: file.relativePath,
            message: `${desc} found in repository — should be in .gitignore`,
          });

          // Check for actual secrets in the file
          for (let i = 0; i < file.lines.length; i++) {
            const line = file.lines[i]!;
            if (SECRET_IN_ENV_RE.test(line) && !line.trimStart().startsWith("#")) {
              findings.push({
                rule: "hidden-files",
                severity: "critical",
                file: file.relativePath,
                line: i + 1,
                message: "Hardcoded secret in environment file",
                evidence: line.replace(/=.*/, "=***").slice(0, 80),
              });
            }
          }
          break;
        }
      }
    }

    return findings;
  },
};
