import type { Rule, Finding, ScannedFile } from "../types.js";

/**
 * Rule: typosquatting
 * Detects potentially typosquatted npm package names.
 */

// Known popular packages and their common typos
const TYPOSQUAT_MAP: Record<string, string[]> = {
  lodash: ["1odash", "lodsh", "lodashs", "lodahs"],
  express: ["expresss", "expres", "exress", "exppress"],
  axios: ["axois", "axio", "axioss", "axiso"],
  react: ["raect", "reacct", "reactt"],
  chalk: ["chalks", "chalkk", "chak"],
  commander: ["comander", "commanderr", "commmander"],
  "node-fetch": ["node-ftch", "nodefetch", "node-fetchh"],
  request: ["reqeust", "requets", "reuqest"],
  mongoose: ["mongose", "mongosse", "mongooose"],
  webpack: ["webpck", "webpackk", "weback"],
  eslint: ["eslintt", "eslnt", "elint"],
  typescript: ["typscript", "typescipt", "typesript"],
};

export const typosquattingRule: Rule = {
  id: "typosquatting",
  name: "Dependency Typosquatting",
  description: "Detects potentially typosquatted package names in dependencies",

  run(files: ScannedFile[]): Finding[] {
    const findings: Finding[] = [];

    const pkgJson = files.find(
      (f) => f.relativePath === "package.json" || f.relativePath.endsWith("/package.json"),
    );
    if (!pkgJson) return findings;

    try {
      const pkg = JSON.parse(pkgJson.content);
      const allDeps = {
        ...pkg.dependencies,
        ...pkg.devDependencies,
        ...pkg.peerDependencies,
        ...pkg.optionalDependencies,
      };

      for (const depName of Object.keys(allDeps)) {
        for (const [legitimate, typos] of Object.entries(TYPOSQUAT_MAP)) {
          if (typos.includes(depName.toLowerCase())) {
            findings.push({
              rule: "typosquatting",
              severity: "critical",
              file: pkgJson.relativePath,
              message: `Suspicious package "${depName}" — possible typosquat of "${legitimate}"`,
            });
          }
        }
      }
    } catch {
      // ignore parse errors
    }

    return findings;
  },
};
