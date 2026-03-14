import { readFileSync, statSync, readdirSync, mkdtempSync, rmSync, existsSync } from "fs";
import { join, relative, extname, basename, dirname } from "path";
import { execSync } from "child_process";
import { tmpdir } from "os";
import type { ScannedFile, FileContext } from "../types.js";

const SKIP_DIRS = new Set([
  "node_modules", ".git", "dist", "build", "__pycache__", ".venv", "venv",
  "site-packages", "dist-packages", ".eggs", "egg-info",
  "Lib", "lib64", ".tox", ".nox",
]);

const CODE_EXTS = new Set([
  ".ts", ".js", ".mjs", ".cjs", ".tsx", ".jsx",
  ".py", ".sh", ".bash", ".zsh",
  ".go", ".rs",
  ".json", ".yaml", ".yml", ".toml",
  ".md",
]);

const MAX_FILE_SIZE = 512 * 1024; // 512 KB

/** Extract .difypkg (zip) to a temp directory and return the path */
export function extractDifypkg(filePath: string): string {
  const tmpDir = mkdtempSync(join(tmpdir(), "agent-shield-difypkg-"));
  try {
    execSync(`unzip -q -o "${filePath}" -d "${tmpDir}"`, { stdio: "pipe" });
  } catch {
    // If unzip not available, try python
    try {
      execSync(`python3 -c "import zipfile; zipfile.ZipFile('${filePath}').extractall('${tmpDir}')"`, { stdio: "pipe" });
    } catch {
      rmSync(tmpDir, { recursive: true, force: true });
      throw new Error(`Cannot extract ${filePath}: neither unzip nor python3 available`);
    }
  }
  return tmpDir;
}

/** Clean up a temp directory */
export function cleanupTemp(tmpDir: string): void {
  try {
    rmSync(tmpDir, { recursive: true, force: true });
  } catch {
    // ignore cleanup errors
  }
}

/** Recursively collect scannable files from a directory */
export function collectFiles(dir: string, base?: string): ScannedFile[] {
  const root = base ?? dir;
  const files: ScannedFile[] = [];

  let entries: string[];
  try {
    entries = readdirSync(dir);
  } catch {
    return files;
  }

  for (const name of entries) {
    if (name.startsWith(".") && name !== ".env") continue;
    if (SKIP_DIRS.has(name)) continue;

    const fullPath = join(dir, name);
    let stat;
    try {
      stat = statSync(fullPath);
    } catch {
      continue;
    }

    if (stat.isDirectory()) {
      files.push(...collectFiles(fullPath, root));
    } else if (stat.isFile()) {
      const ext = extname(name).toLowerCase();
      if (!CODE_EXTS.has(ext) && name !== "SKILL.md") continue;
      if (stat.size > MAX_FILE_SIZE) continue;

      try {
        const content = readFileSync(fullPath, "utf-8");
        const relPath = relative(root, fullPath);
        const sdkResult = detectKnownSdks(content);
        files.push({
          filePath: fullPath,
          relativePath: relPath,
          content,
          lines: content.split("\n"),
          ext,
          context: detectFileContext(relPath, name),
          usesKnownSdk: sdkResult.length > 0,
          detectedSdks: sdkResult.length > 0 ? sdkResult : undefined,
        });
      } catch {
        // skip unreadable files
      }
    }
  }

  return files;
}

/** Count total lines across files */
export function totalLines(files: ScannedFile[]): number {
  return files.reduce((sum, f) => sum + f.lines.length, 0);
}

/** Detect file context for false positive reduction */
function detectFileContext(relativePath: string, fileName: string): FileContext {
  const lowerPath = relativePath.toLowerCase();
  const lowerName = fileName.toLowerCase();
  const dirName = dirname(lowerPath).toLowerCase();

  // Test files
  if (
    lowerName.includes(".test.") || lowerName.includes(".spec.") ||
    lowerName.includes("_test.") || lowerName.includes("_spec.") ||
    lowerPath.includes("__tests__") || lowerPath.includes("/tests/") ||
    lowerPath.startsWith("tests/") || lowerPath.startsWith("test/") ||
    lowerPath.includes("/performance/") || lowerPath.startsWith("performance/") ||
    lowerPath.includes("/benchmark/") || lowerPath.startsWith("benchmark/") ||
    lowerName.startsWith("locustfile") || lowerName.startsWith("conftest") ||
    lowerName === "jest.config.js" || lowerName === "vitest.config.ts"
  ) {
    return "test";
  }

  // Deploy / CI scripts
  if (
    lowerPath.includes("deploy") || lowerPath.includes("ci/") ||
    lowerPath.includes(".github/") || lowerPath.includes("scripts/") ||
    lowerPath.includes("infra/") || lowerPath.includes("ops/") ||
    lowerName.includes("deploy") || lowerName.includes("release") ||
    lowerName === "dockerfile" || lowerName === "makefile"
  ) {
    return "deploy";
  }

  // Config files
  if (
    [".json", ".yaml", ".yml", ".toml"].includes(extname(lowerName)) &&
    !lowerName.includes("skill")
  ) {
    return "config";
  }

  // Documentation
  if (extname(lowerName) === ".md") {
    return "docs";
  }

  // Shell scripts (standalone)
  if ([".sh", ".bash", ".zsh"].includes(extname(lowerName))) {
    return "script";
  }

  return "source";
}

// ─── Known safe SDK detection ───

/** Well-known SDK package prefixes that indicate legitimate API usage */
const KNOWN_SDK_PATTERNS: Array<{ pattern: RegExp; name: string }> = [
  // Feishu / Lark
  { pattern: /@larksuiteoapi\//, name: "@larksuiteoapi/*" },
  { pattern: /feishu-sdk/, name: "feishu-sdk" },
  // AWS
  { pattern: /@aws-sdk\//, name: "@aws-sdk/*" },
  { pattern: /aws-sdk/, name: "aws-sdk" },
  // Google Cloud
  { pattern: /@google-cloud\//, name: "@google-cloud/*" },
  { pattern: /googleapis/, name: "googleapis" },
  // Azure
  { pattern: /@azure\//, name: "@azure/*" },
  // Stripe
  { pattern: /["']stripe["']/, name: "stripe" },
  // Twilio
  { pattern: /["']twilio["']/, name: "twilio" },
  // SendGrid
  { pattern: /@sendgrid\//, name: "@sendgrid/*" },
  // Slack
  { pattern: /@slack\//, name: "@slack/*" },
  // Discord
  { pattern: /discord\.js/, name: "discord.js" },
  // Telegram
  { pattern: /node-telegram-bot-api|telegraf/, name: "telegram-bot" },
  // OpenAI / Anthropic
  { pattern: /["']openai["']/, name: "openai" },
  { pattern: /@anthropic-ai\//, name: "@anthropic-ai/*" },
  // Firebase
  { pattern: /firebase-admin|@firebase\//, name: "firebase" },
  // Supabase
  { pattern: /@supabase\//, name: "@supabase/*" },
  // GitHub Octokit
  { pattern: /@octokit\//, name: "@octokit/*" },
  // Python SDKs (import style)
  { pattern: /from\s+boto3\s+import|import\s+boto3/, name: "boto3" },
  { pattern: /from\s+google\.cloud\s+import/, name: "google-cloud-python" },
  { pattern: /from\s+azure\.\w+\s+import/, name: "azure-python" },
];

/** Import patterns to match */
const IMPORT_RE = /(?:import\s+.*?from\s+["']|require\s*\(\s*["']|from\s+\S+\s+import)/;

/**
 * Detect known safe SDKs in file content based on import statements.
 * Returns list of detected SDK names.
 */
function detectKnownSdks(content: string): string[] {
  const detected: string[] = [];
  const lines = content.split("\n");

  for (const line of lines) {
    if (!IMPORT_RE.test(line)) continue;
    for (const { pattern, name } of KNOWN_SDK_PATTERNS) {
      if (pattern.test(line) && !detected.includes(name)) {
        detected.push(name);
      }
    }
  }

  return detected;
}
