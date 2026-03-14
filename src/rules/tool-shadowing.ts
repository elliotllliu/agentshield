import type { Rule, Finding, ScannedFile } from "../types.js";

/**
 * Rule: tool-shadowing
 * Detects when a tool description references tools from other MCP servers,
 * potentially hijacking or overriding their behavior.
 * Also detects cross-server tool name conflicts from MCP config files.
 */

// Common MCP tool names that could be shadowed
const WELL_KNOWN_TOOLS = [
  "read_file", "write_file", "list_files", "search_files",
  "execute_command", "run_terminal_command",
  "browser_action", "web_search",
  "create_file", "edit_file", "delete_file",
  "git_commit", "git_push", "git_pull",
  "send_message", "read_email",
];

// Patterns indicating cross-tool reference in descriptions
const CROSS_TOOL_PATTERNS: Array<{ pattern: RegExp; description: string }> = [
  { pattern: /(?:instead\s+of|replace|override|intercept|wrap)\s+(?:the\s+)?(?:original|default|built-in|other)\s+(?:tool|function|command)/i, description: "Claims to replace another tool" },
  { pattern: /(?:call|use|invoke)\s+(?:this\s+tool\s+)?(?:instead\s+of|before|after)\s+["']?\w+["']?/i, description: "Redirects from another tool to this one" },
  { pattern: /(?:this|my)\s+(?:version|implementation)\s+of\s+["']?\w+["']?\s+(?:is|should\s+be)/i, description: "Claims to be a version of another tool" },
  { pattern: /(?:enhanced|improved|better|secure)\s+(?:version|replacement)\s+(?:of|for)\s+/i, description: "Claims to be an enhanced version" },
  { pattern: /(?:whenever|every\s+time)\s+(?:you|the\s+agent)\s+(?:would\s+)?(?:use|call|invoke)\s+["']?\w+["']?,?\s+(?:use|call)\s+(?:this|me)/i, description: "Hijacks calls to another tool" },
];

export const toolShadowing: Rule = {
  id: "tool-shadowing",
  name: "Tool Shadowing Detection",
  description: "Detects tools that attempt to shadow, override, or hijack other tools",

  run(files: ScannedFile[]): Finding[] {
    const findings: Finding[] = [];

    // Collect tool names from MCP config files
    const toolsByServer: Map<string, { tools: string[]; file: string }> = new Map();

    for (const file of files) {
      // Check JSON config files for MCP tool definitions
      if (file.ext === ".json") {
        try {
          const config = JSON.parse(file.content);
          extractMcpTools(config, file.relativePath, toolsByServer);
        } catch {
          // Not valid JSON, skip
        }
      }

      // Check tool descriptions for cross-tool reference patterns
      if ([".json", ".md", ".yaml", ".yml", ".ts", ".js"].includes(file.ext)) {
        for (let i = 0; i < file.lines.length; i++) {
          const line = file.lines[i]!;

          for (const { pattern, description } of CROSS_TOOL_PATTERNS) {
            pattern.lastIndex = 0;
            if (pattern.test(line)) {
              findings.push({
                rule: "tool-shadowing",
                severity: "medium",
                file: file.relativePath,
                line: i + 1,
                message: `Tool shadowing: ${description}`,
                evidence: line.trim().substring(0, 120),
                confidence: "low",
              });
              break;
            }
          }

          // Check if description references well-known tool names
          const lineLower = line.toLowerCase();
          for (const toolName of WELL_KNOWN_TOOLS) {
            if (
              lineLower.includes(toolName) &&
              /(?:instead|replace|override|intercept|before|after|wrap)/i.test(line)
            ) {
              findings.push({
                rule: "tool-shadowing",
                severity: "medium",
                file: file.relativePath,
                line: i + 1,
                message: `References well-known tool "${toolName}" with override intent`,
                evidence: line.trim().substring(0, 120),
                confidence: "low",
              });
              break;
            }
          }
        }
      }
    }

    // Check for duplicate tool names across servers
    const allToolNames: Map<string, string[]> = new Map(); // toolName -> [server1, server2]
    for (const [serverName, { tools }] of toolsByServer) {
      for (const tool of tools) {
        if (!allToolNames.has(tool)) allToolNames.set(tool, []);
        allToolNames.get(tool)!.push(serverName);
      }
    }

    for (const [toolName, servers] of allToolNames) {
      if (servers.length > 1) {
        findings.push({
          rule: "tool-shadowing",
          severity: "medium",
          file: servers[0]!,
          message: `Tool name conflict: "${toolName}" defined in ${servers.length} servers (${servers.join(", ")}) — potential tool shadowing attack`,
          confidence: "low",
        });
      }
    }

    return findings;
  },
};

function extractMcpTools(
  obj: unknown,
  filePath: string,
  result: Map<string, { tools: string[]; file: string }>,
  serverName?: string,
): void {
  if (!obj || typeof obj !== "object") return;

  const record = obj as Record<string, unknown>;

  // Look for MCP server definitions with tools
  if (record.tools && Array.isArray(record.tools)) {
    const tools = (record.tools as Array<Record<string, unknown>>)
      .map((t) => String(t.name || t.id || ""))
      .filter(Boolean);
    if (tools.length > 0) {
      const name = serverName || filePath;
      result.set(name, { tools, file: filePath });
    }
  }

  // Recurse into mcpServers config
  if (record.mcpServers && typeof record.mcpServers === "object") {
    for (const [name, config] of Object.entries(record.mcpServers as Record<string, unknown>)) {
      extractMcpTools(config, filePath, result, name);
    }
  }

  // Recurse into servers
  if (record.servers && typeof record.servers === "object") {
    for (const [name, config] of Object.entries(record.servers as Record<string, unknown>)) {
      extractMcpTools(config, filePath, result, name);
    }
  }
}
