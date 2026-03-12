import matter from "gray-matter";
import type { Rule, Finding, ScannedFile } from "../types.js";

/**
 * Rule: excessive-perms
 * Detects skills that request too many or dangerous permissions.
 */

const DANGEROUS_PERMS = new Set(["exec", "admin", "root", "sudo", "network", "browser"]);
const MAX_REASONABLE_PERMS = 5;

export const excessivePermsRule: Rule = {
  id: "excessive-perms",
  name: "Excessive Permissions",
  description: "Detects skills requesting too many or dangerous permissions",

  run(files: ScannedFile[]): Finding[] {
    const findings: Finding[] = [];

    const skillMd = files.find(
      (f) => f.relativePath === "SKILL.md" || f.relativePath.endsWith("/SKILL.md"),
    );
    if (!skillMd) return findings;

    let permissions: string[] = [];
    try {
      const { data } = matter(skillMd.content);
      if (Array.isArray(data.permissions)) {
        permissions = data.permissions.filter((p: unknown) => typeof p === "string");
      }
    } catch {
      return findings;
    }

    // Check for dangerous permissions
    for (const perm of permissions) {
      if (DANGEROUS_PERMS.has(perm.toLowerCase())) {
        findings.push({
          rule: "excessive-perms",
          severity: "warning",
          file: skillMd.relativePath,
          message: `Requests dangerous permission: '${perm}'`,
        });
      }
    }

    // Check for excessive number of permissions
    if (permissions.length > MAX_REASONABLE_PERMS) {
      findings.push({
        rule: "excessive-perms",
        severity: "warning",
        file: skillMd.relativePath,
        message: `Requests ${permissions.length} permissions (threshold: ${MAX_REASONABLE_PERMS}) — review if all are necessary`,
      });
    }

    return findings;
  },
};
