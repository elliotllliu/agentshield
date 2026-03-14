import type { Rule, Finding, ScannedFile } from "../types.js";

/**
 * Rule: mcp-manifest
 * Validates MCP (Model Context Protocol) server configurations.
 *
 * Checks:
 * 1. Declared tools/resources vs actual code behavior
 * 2. Overly broad tool descriptions that could mislead agents
 * 3. Undeclared file system / network / exec capabilities
 * 4. Suspicious tool names or descriptions
 */

// Patterns indicating MCP server tool registration
const TOOL_REGISTER_RE =
  /\.tool\s*\(|addTool\s*\(|registerTool\s*\(|server\.setRequestHandler.*ListTools|tools:\s*\[/;

// Patterns for MCP resource registration
const RESOURCE_REGISTER_RE =
  /\.resource\s*\(|addResource\s*\(|registerResource\s*\(|server\.setRequestHandler.*ListResources|resources:\s*\[/;

// Dangerous patterns in tool implementations
const DANGEROUS_TOOL_PATTERNS: Array<{ pattern: RegExp; desc: string; severity: "low" | "low" }> = [
  { pattern: /child_process|execSync|exec\(|spawn\(/, desc: "Tool executes shell commands", severity: "low" },
  { pattern: /fs\.unlink|fs\.rmdir|fs\.rm\b|rimraf/, desc: "Tool deletes files", severity: "low" },
  { pattern: /fs\.writeFile|fs\.appendFile|fs\.createWriteStream/, desc: "Tool writes to file system", severity: "low" },
  { pattern: /fetch\s*\(|axios|http\.request|https\.request/, desc: "Tool makes outbound HTTP requests", severity: "low" },
  { pattern: /eval\s*\(|new\s+Function\s*\(/, desc: "Tool uses dynamic code execution", severity: "low" },
  { pattern: /\.ssh|\.aws|\.env\b|credentials|secret/i, desc: "Tool accesses sensitive paths/credentials", severity: "low" },
];

// Suspicious tool name/description patterns
const SUSPICIOUS_TOOL_DESC: Array<{ pattern: RegExp; desc: string }> = [
  { pattern: /run.*any.*command|execute.*arbitrary|shell.*access/i, desc: "Tool claims unrestricted command execution" },
  { pattern: /access.*all.*files|read.*entire.*filesystem/i, desc: "Tool claims full filesystem access" },
  { pattern: /send.*data.*to|upload.*to|transmit.*to/i, desc: "Tool description mentions data transmission" },
  { pattern: /modify.*system|change.*config/i, desc: "Tool claims system modification capability" },
];

// Dynamic tool loading patterns (runtime tool registration from external sources)
const DYNAMIC_TOOL_PATTERNS: Array<{ pattern: RegExp; desc: string }> = [
  { pattern: /(?:fetch|axios|got|request)\s*\([^)]*(?:tools|schema|manifest|definition)/i, desc: "Fetches tool definitions from external URL" },
  { pattern: /(?:import|require|load)\s*\([^)]*(?:tool|plugin|extension)\s*(?:url|endpoint|remote)/i, desc: "Dynamically imports tools from remote source" },
  { pattern: /(?:register|add)Tool\s*\(\s*(?:await\s+)?(?:fetch|get|load)/i, desc: "Registers tools loaded from external source" },
  { pattern: /tools\s*=\s*(?:await\s+)?(?:fetch|axios|got)\s*\(/i, desc: "Tool list fetched from remote URL" },
];

export const mcpManifestRule: Rule = {
  id: "mcp-manifest",
  name: "MCP Server Validation",
  description: "Validates MCP server tool/resource declarations against actual code behavior",

  run(files: ScannedFile[]): Finding[] {
    const findings: Finding[] = [];

    // Entity count and config checks work on any JSON with mcpServers
    checkEntityCount(files, findings);

    // Detect if this is an MCP server project for deeper checks
    const isMcpServer = detectMcpServer(files);
    if (!isMcpServer) return findings;

    // Check for MCP manifest/config files
    checkMcpConfig(files, findings);

    // Analyze tool implementations for dangerous patterns
    checkToolImplementations(files, findings);

    // Check tool descriptions for suspicious claims
    checkToolDescriptions(files, findings);

    // Check for dynamic tool loading from external sources
    checkDynamicToolLoading(files, findings);

    // Check if tools are registered but have no input validation
    checkInputValidation(files, findings);

    return findings;
  },
};

function detectMcpServer(files: ScannedFile[]): boolean {
  for (const file of files) {
    // Check package.json for MCP-related deps
    if (file.relativePath === "package.json") {
      try {
        const pkg = JSON.parse(file.content);
        const allDeps = { ...pkg.dependencies, ...pkg.devDependencies };
        if (
          allDeps["@modelcontextprotocol/sdk"] ||
          allDeps["@anthropic-ai/sdk"] ||
          pkg.mcp
        ) {
          return true;
        }
      } catch {
        // ignore parse errors
      }
    }

    // Check for MCP imports in code
    if (file.ext === ".ts" || file.ext === ".js" || file.ext === ".mjs") {
      if (
        file.content.includes("@modelcontextprotocol/sdk") ||
        file.content.includes("McpServer") ||
        file.content.includes("createMcpServer") ||
        TOOL_REGISTER_RE.test(file.content)
      ) {
        return true;
      }
    }

    // Check for mcp.json or similar config
    if (
      file.relativePath === "mcp.json" ||
      file.relativePath.endsWith("/mcp.json")
    ) {
      return true;
    }
  }
  return false;
}

function checkMcpConfig(files: ScannedFile[], findings: Finding[]): void {
  const mcpConfig = files.find(
    (f) => f.relativePath === "mcp.json" || f.relativePath.endsWith("/mcp.json"),
  );

  if (mcpConfig) {
    try {
      const config = JSON.parse(mcpConfig.content);

      // Check for overly broad permissions
      if (config.permissions) {
        const perms = Array.isArray(config.permissions)
          ? config.permissions
          : Object.keys(config.permissions);
        if (perms.length > 5) {
          findings.push({
            rule: "mcp-manifest",
            severity: "low",
            file: mcpConfig.relativePath,
            message: `MCP config declares ${perms.length} permissions — consider reducing scope`,
            confidence: "low",
          });
        }
      }

      // Check for wildcard or dangerous permissions
      const configStr = JSON.stringify(config);
      if (configStr.includes('"*"') || configStr.includes('"all"')) {
        findings.push({
          rule: "mcp-manifest",
          severity: "low",
          file: mcpConfig.relativePath,
          message: "MCP config uses wildcard/all permissions",
          confidence: "low",
        });
      }
    } catch {
      findings.push({
        rule: "mcp-manifest",
        severity: "low",
        file: mcpConfig.relativePath,
        message: "Invalid JSON in MCP config file",
        confidence: "low",
      });
    }
  }
}

function checkToolImplementations(files: ScannedFile[], findings: Finding[]): void {
  const codeFiles = files.filter(
    (f) => f.ext === ".ts" || f.ext === ".js" || f.ext === ".mjs" || f.ext === ".cjs",
  );

  for (const file of codeFiles) {
    // Only check files that register tools
    if (!TOOL_REGISTER_RE.test(file.content) && !RESOURCE_REGISTER_RE.test(file.content)) {
      continue;
    }

    for (let i = 0; i < file.lines.length; i++) {
      const line = file.lines[i]!;
      const trimmed = line.trimStart();
      if (trimmed.startsWith("//") || trimmed.startsWith("*")) continue;

      for (const { pattern, desc, severity } of DANGEROUS_TOOL_PATTERNS) {
        if (pattern.test(line)) {
          findings.push({
            rule: "mcp-manifest",
            severity,
            file: file.relativePath,
            line: i + 1,
            message: `MCP tool: ${desc}`,
            evidence: line.trim().slice(0, 120),
            confidence: "low",
          });
          break;
        }
      }
    }
  }
}

function checkToolDescriptions(files: ScannedFile[], findings: Finding[]): void {
  const codeFiles = files.filter(
    (f) => f.ext === ".ts" || f.ext === ".js" || f.ext === ".mjs",
  );

  for (const file of codeFiles) {
    // Look for tool description strings
    for (let i = 0; i < file.lines.length; i++) {
      const line = file.lines[i]!;

      for (const { pattern, desc } of SUSPICIOUS_TOOL_DESC) {
        if (pattern.test(line)) {
          findings.push({
            rule: "mcp-manifest",
            severity: "low",
            file: file.relativePath,
            line: i + 1,
            message: `Suspicious MCP tool description: ${desc}`,
            evidence: line.trim().slice(0, 120),
            confidence: "low",
          });
          break;
        }
      }
    }
  }
}

function checkInputValidation(files: ScannedFile[], findings: Finding[]): void {
  const codeFiles = files.filter(
    (f) => f.ext === ".ts" || f.ext === ".js" || f.ext === ".mjs",
  );

  for (const file of codeFiles) {
    if (!TOOL_REGISTER_RE.test(file.content)) continue;

    // Check for tools that accept path inputs without validation
    const hasPathInput = /path|file|dir|folder/i.test(file.content);
    const hasPathValidation = /sanitize|validate|allowlist|whitelist|isAbsolute|normalize|resolve/i.test(file.content);
    const hasTraversalCheck = /\.\.\//i.test(file.content) || /path.*traversal/i.test(file.content);

    if (hasPathInput && !hasPathValidation && !hasTraversalCheck) {
      findings.push({
        rule: "mcp-manifest",
        severity: "low",
        file: file.relativePath,
        message: "MCP tool accepts path inputs but has no visible path validation/sanitization",
        confidence: "low",
      });
    }
  }
}

/** Check for dynamic tool loading from external sources */
function checkDynamicToolLoading(files: ScannedFile[], findings: Finding[]): void {
  const codeFiles = files.filter(
    (f) => f.ext === ".ts" || f.ext === ".js" || f.ext === ".mjs" || f.ext === ".py",
  );

  for (const file of codeFiles) {
    for (let i = 0; i < file.lines.length; i++) {
      const line = file.lines[i]!;
      const trimmed = line.trimStart();
      if (trimmed.startsWith("//") || trimmed.startsWith("#") || trimmed.startsWith("*")) continue;

      for (const { pattern, desc } of DYNAMIC_TOOL_PATTERNS) {
        if (pattern.test(line)) {
          findings.push({
            rule: "mcp-manifest",
            severity: "low",
            file: file.relativePath,
            line: i + 1,
            message: `Dynamic tool loading: ${desc}`,
            evidence: line.trim().slice(0, 120),
            confidence: "low",
          });
          break;
        }
      }
    }
  }
}

/** Check entity count (Snyk W002: too many tools/resources) */
function checkEntityCount(files: ScannedFile[], findings: Finding[]): void {
  for (const file of files) {
    if (file.ext !== ".json") continue;
    try {
      const config = JSON.parse(file.content);
      const servers = config.mcpServers || config.servers || {};

      for (const [serverName, serverConfig] of Object.entries(servers)) {
        if (!serverConfig || typeof serverConfig !== "object") continue;
        const sc = serverConfig as Record<string, unknown>;
        const tools = Array.isArray(sc.tools) ? sc.tools.length : 0;
        const resources = Array.isArray(sc.resources) ? sc.resources.length : 0;
        const prompts = Array.isArray(sc.prompts) ? sc.prompts.length : 0;
        const total = tools + resources + prompts;

        if (total > 100) {
          findings.push({
            rule: "mcp-manifest",
            severity: "low",
            file: file.relativePath,
            message: `W002: Server "${serverName}" exposes ${total} entities (${tools} tools, ${resources} resources, ${prompts} prompts) — agent performance may degrade above 100`,
            confidence: "low",
          });
        } else if (total > 50) {
          findings.push({
            rule: "mcp-manifest",
            severity: "low",
            file: file.relativePath,
            message: `Server "${serverName}" exposes ${total} entities — consider reducing for optimal agent performance`,
            confidence: "low",
          });
        }
      }
    } catch {
      // Not valid JSON
    }
  }
}
