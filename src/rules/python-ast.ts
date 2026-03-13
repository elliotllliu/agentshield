import type { Rule, Finding, ScannedFile } from "../types.js";
import { execSync } from "node:child_process";
import { writeFileSync, unlinkSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { tmpdir } from "node:os";

/**
 * Rule: python-ast
 * Deep Python security analysis using AST (Abstract Syntax Tree).
 *
 * Advantages over regex:
 * - Distinguishes function calls from strings/comments
 * - Tracks data flow (taint analysis)
 * - Identifies eval/exec with literal vs dynamic arguments
 * - Detects monkey-patching and dynamic attribute access
 * - Near-zero false positives on pattern definitions
 *
 * Requires Python 3.6+ (uses `ast` module from stdlib).
 */

// Resolve the path to the Python analyzer script
// From dist/rules/ → ../../src/analyzers/python_ast.py
const __dirname_module = dirname(fileURLToPath(import.meta.url));
const ANALYZER_PATH = join(__dirname_module, "..", "..", "src", "analyzers", "python_ast.py");

interface AstFinding {
  line: number;
  severity: string;
  rule: string;
  message: string;
  confidence: string;
  file: string;
  error?: string;
}

let pythonAvailable: boolean | null = null;

function checkPython(): boolean {
  if (pythonAvailable !== null) return pythonAvailable;
  try {
    execSync("python3 --version", { stdio: "pipe" });
    pythonAvailable = true;
  } catch {
    pythonAvailable = false;
  }
  return pythonAvailable;
}

function runAstAnalysis(files: ScannedFile[]): AstFinding[] {
  if (!checkPython()) return [];

  const pyFiles = files.filter(f => f.ext === ".py" && f.context !== "test");
  if (pyFiles.length === 0) return [];

  // Write files to temp directory for analysis
  const tmpDir = join(tmpdir(), `agentshield-ast-${Date.now()}`);
  try {
    execSync(`mkdir -p ${tmpDir}`, { stdio: "pipe" });
  } catch { return []; }

  const filePaths: string[] = [];
  for (const file of pyFiles) {
    const safeName = file.relativePath.replace(/\//g, "__");
    const tmpPath = join(tmpDir, safeName);
    try {
      writeFileSync(tmpPath, file.content, "utf-8");
      filePaths.push(tmpPath);
    } catch { /* skip */ }
  }

  if (filePaths.length === 0) {
    cleanup(tmpDir);
    return [];
  }

  try {
    // Run the Python AST analyzer
    const result = execSync(
      `python3 "${ANALYZER_PATH}" ${filePaths.map(p => `"${p}"`).join(" ")}`,
      { stdio: ["pipe", "pipe", "pipe"], timeout: 30000, maxBuffer: 10 * 1024 * 1024 }
    );

    const findings: AstFinding[] = JSON.parse(result.toString());

    // Map temp filenames back to original relative paths
    for (const finding of findings) {
      for (const file of pyFiles) {
        const safeName = file.relativePath.replace(/\//g, "__");
        if (finding.file === safeName) {
          finding.file = file.relativePath;
          break;
        }
      }
    }

    return findings.filter(f => !f.error);
  } catch {
    return [];
  } finally {
    cleanup(tmpDir);
  }
}

function cleanup(dir: string) {
  try {
    execSync(`rm -rf "${dir}"`, { stdio: "pipe" });
  } catch { /* ignore */ }
}

export const pythonAstRule: Rule = {
  id: "python-ast",
  name: "Python AST Deep Analysis",
  description: "AST-based security analysis for Python code (taint tracking, precise call analysis)",

  run(files: ScannedFile[]): Finding[] {
    const astFindings = runAstAnalysis(files);

    return astFindings.map(f => ({
      rule: f.rule || "python-ast",
      severity: (f.severity === "high" ? "high" : f.severity === "medium" ? "medium" : "low") as "high" | "medium" | "low",
      file: f.file,
      line: f.line,
      message: `[AST] ${f.message}`,
      confidence: (f.confidence || "medium") as "high" | "medium" | "low",
    }));
  },
};
