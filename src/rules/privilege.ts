import matter from "gray-matter";
import type { Rule, Finding, ScannedFile, SkillMetadata } from "../types.js";

/**
 * Rule: privilege
 * Compares declared permissions in SKILL.md vs actual API usage in code.
 */

// Map of capabilities to code patterns that indicate their use
const CAPABILITY_PATTERNS: Record<string, RegExp> = {
  exec: /child_process|execSync|exec\(|spawn\(|os\.system|subprocess|ShellAction/i,
  read: /readFile|readFileSync|fs\.read|open\(.*["']r/i,
  write: /writeFile|writeFileSync|fs\.write|appendFile|open\(.*["']w/i,
  web_fetch: /fetch\s*\(|axios|http\.request|https\.request|requests\.(get|post)/i,
  browser: /puppeteer|playwright|selenium|webdriver|BrowserAction/i,
  network: /net\.connect|dgram|WebSocket|Socket/i,
};

export const privilegeRule: Rule = {
  id: "privilege",
  name: "Privilege Mismatch",
  description: "Compares declared permissions in SKILL.md against actual code behavior",

  run(files: ScannedFile[]): Finding[] {
    const findings: Finding[] = [];

    // Find SKILL.md
    const skillMd = files.find(
      (f) => f.relativePath === "SKILL.md" || f.relativePath.endsWith("/SKILL.md"),
    );
    if (!skillMd) {
      // No SKILL.md — can't check permissions
      findings.push({
        rule: "privilege",
        severity: "low",
        file: ".",
        message: "No SKILL.md found — permission analysis skipped",
        confidence: "medium",
      });
      return findings;
    }

    // Parse frontmatter
    let meta: SkillMetadata = {};
    try {
      const { data } = matter(skillMd.content);
      meta = data as SkillMetadata;
    } catch {
      // not valid frontmatter
    }

    // Extract declared permissions (from frontmatter or body)
    const declaredPerms = new Set<string>();
    if (Array.isArray(meta.permissions)) {
      for (const p of meta.permissions) {
        if (typeof p === "string") declaredPerms.add(p.toLowerCase());
      }
    }

    // Also scan SKILL.md body for permission keywords
    const bodyPermsMatch = skillMd.content.match(/permissions?:\s*([\w,\s]+)/i);
    if (bodyPermsMatch) {
      for (const p of bodyPermsMatch[1]!.split(/[,\s]+/)) {
        if (p.trim()) declaredPerms.add(p.trim().toLowerCase());
      }
    }

    // Scan code files for actual capability usage
    const codeFiles = files.filter(
      (f) => f.ext !== ".md" && f.ext !== ".json" && f.ext !== ".yaml" && f.ext !== ".yml",
    );

    const usedCapabilities = new Set<string>();
    const capabilityLocations: Record<string, { file: string; line: number }[]> = {};

    for (const file of codeFiles) {
      for (const [cap, pattern] of Object.entries(CAPABILITY_PATTERNS)) {
        for (let i = 0; i < file.lines.length; i++) {
          if (pattern.test(file.lines[i]!)) {
            usedCapabilities.add(cap);
            if (!capabilityLocations[cap]) capabilityLocations[cap] = [];
            capabilityLocations[cap]!.push({ file: file.relativePath, line: i + 1 });
          }
        }
      }
    }

    // Report undeclared capabilities
    for (const cap of usedCapabilities) {
      if (declaredPerms.size > 0 && !declaredPerms.has(cap)) {
        const locations = capabilityLocations[cap] || [];
        const first = locations[0];
        findings.push({
          rule: "privilege",
          severity: "low",
          file: first?.file || skillMd.relativePath,
          line: first?.line,
          message: `Code uses '${cap}' capability but SKILL.md doesn't declare it (found in ${locations.length} location${locations.length > 1 ? "s" : ""})`,
          confidence: "medium",
        });
      }
    }

    // Report declared but unused permissions
    for (const perm of declaredPerms) {
      if (!usedCapabilities.has(perm) && CAPABILITY_PATTERNS[perm]) {
        findings.push({
          rule: "privilege",
          severity: "low",
          file: skillMd.relativePath,
          message: `SKILL.md declares '${perm}' permission but code doesn't appear to use it`,
          confidence: "medium",
        });
      }
    }

    // Report used capabilities as info
    if (usedCapabilities.size > 0) {
      findings.push({
        rule: "privilege",
        severity: "low",
        file: skillMd.relativePath,
        message: `Detected capabilities: ${[...usedCapabilities].join(", ")}`,
        confidence: "medium",
      });
    }

    return findings;
  },
};
