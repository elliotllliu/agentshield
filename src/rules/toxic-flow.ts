import type { Rule, Finding, ScannedFile } from "../types.js";

/**
 * Rule: toxic-flow
 * Detects dangerous tool capability combinations that could enable
 * cross-tool data exfiltration or destructive attacks.
 *
 * Based on Snyk Agent Scan:
 * - TF001: Data Leak Toxic Flow (untrusted input → private data → public sink)
 * - TF002: Destructive Toxic Flow (untrusted input → destructive action)
 *
 * Analyzes MCP config files to classify tools and detect risky combinations.
 */

/** Tool capability classification */
interface ToolCapability {
  name: string;
  server: string;
  untrustedContent: boolean;  // Returns data from external/user-controlled sources
  privateData: boolean;       // Accesses sensitive user data
  publicSink: boolean;        // Sends data to external destinations
  destructive: boolean;       // Performs irreversible operations
  reasons: string[];
}

// Patterns for classifying tool capabilities
const UNTRUSTED_INDICATORS = [
  /(?:fetch|browse|scrape|crawl|read)[_\s]*(?:url|web|page|site|link)/i,
  /(?:user[- ]?(?:provided|input|supplied)|external|third[- ]?party)/i,
  /(?:search|query)\s+(?:the\s+)?(?:web|internet|google|bing)/i,
  /(?:download|get)\s+(?:from|content)/i,
  /(?:parse|read)\s+(?:email|message|comment|post|tweet|rss)/i,
  /browse\s+(?:any|arbitrary)\s+(?:web|url|page|site)/i,
];

const PRIVATE_DATA_INDICATORS = [
  /(?:read|access|get|list)\s*(?:file|directory|folder|document)/i,
  /(?:database|db|sql|query|select)\s/i,
  /(?:user\s+data|personal|private|confidential|sensitive)/i,
  /(?:credential|password|secret|token|key)\s/i,
  /(?:history|log|conversation|chat|message)/i,
  /(?:config|setting|preference|profile)/i,
];

const PUBLIC_SINK_INDICATORS = [
  /(?:send|post|publish|share|upload|transmit|forward)\s/i,
  /(?:email|message|notification|webhook|api\s+call)/i,
  /(?:slack|discord|telegram|whatsapp|twitter|github)/i,
  /(?:http|https|request|fetch)\s*\(/i,
  /(?:write|save|export)\s+(?:to\s+)?(?:external|remote|cloud)/i,
];

const DESTRUCTIVE_INDICATORS = [
  /(?:delete|remove|drop|truncate|destroy|purge|wipe|erase)/i,
  /(?:overwrite|replace|modify|update|alter)\s+(?:file|data|record|config)/i,
  /(?:execute|run|exec|spawn|shell)\s+(?:command|script|process)/i,
  /(?:format|reset|factory\s+reset|reinstall)/i,
  /(?:revoke|disable|block|ban|suspend)/i,
];

function classifyTool(name: string, description: string, serverName: string): ToolCapability {
  const cap: ToolCapability = {
    name,
    server: serverName,
    untrustedContent: false,
    privateData: false,
    publicSink: false,
    destructive: false,
    reasons: [],
  };

  const text = `${name} ${description}`.toLowerCase();

  for (const re of UNTRUSTED_INDICATORS) {
    if (re.test(text)) { cap.untrustedContent = true; cap.reasons.push("untrusted-content"); break; }
  }
  for (const re of PRIVATE_DATA_INDICATORS) {
    if (re.test(text)) { cap.privateData = true; cap.reasons.push("private-data"); break; }
  }
  for (const re of PUBLIC_SINK_INDICATORS) {
    if (re.test(text)) { cap.publicSink = true; cap.reasons.push("public-sink"); break; }
  }
  for (const re of DESTRUCTIVE_INDICATORS) {
    if (re.test(text)) { cap.destructive = true; cap.reasons.push("destructive"); break; }
  }

  return cap;
}

/** Extract tools from MCP config JSON */
function extractTools(config: Record<string, unknown>, filePath: string): ToolCapability[] {
  const tools: ToolCapability[] = [];

  const servers = (config.mcpServers || config.servers || {}) as Record<string, unknown>;
  for (const [serverName, serverConfig] of Object.entries(servers)) {
    if (!serverConfig || typeof serverConfig !== "object") continue;
    const sc = serverConfig as Record<string, unknown>;

    // Tools array
    if (Array.isArray(sc.tools)) {
      for (const tool of sc.tools as Array<Record<string, unknown>>) {
        const name = String(tool.name || tool.id || "unknown");
        const desc = String(tool.description || "");
        tools.push(classifyTool(name, desc, serverName));
      }
    }

    // If no tools array, classify the server itself by name/description
    if (!sc.tools) {
      const desc = String(sc.description || sc.command || "");
      tools.push(classifyTool(serverName, desc, serverName));
    }
  }

  return tools;
}

export const toxicFlow: Rule = {
  id: "toxic-flow",
  name: "Toxic Flow Detection",
  description: "Detects dangerous tool combinations that enable cross-tool data exfiltration or destructive attacks",

  run(files: ScannedFile[]): Finding[] {
    const findings: Finding[] = [];
    const allTools: ToolCapability[] = [];

    // Collect tools from all JSON config files
    for (const file of files) {
      if (file.ext !== ".json") continue;
      try {
        const config = JSON.parse(file.content) as Record<string, unknown>;
        const tools = extractTools(config, file.relativePath);
        allTools.push(...tools);
      } catch {
        // Not valid JSON
      }
    }

    if (allTools.length === 0) return findings;

    // TF001: Data Leak — untrusted content + private data + public sink
    const hasUntrusted = allTools.filter(t => t.untrustedContent);
    const hasPrivate = allTools.filter(t => t.privateData);
    const hasSink = allTools.filter(t => t.publicSink);

    if (hasUntrusted.length > 0 && hasPrivate.length > 0 && hasSink.length > 0) {
      findings.push({
        rule: "toxic-flow",
        severity: "critical",
        file: "MCP configuration",
        message: `TF001 Data Leak: Tool combination enables data exfiltration — ` +
          `untrusted input (${hasUntrusted.map(t => t.name).join(", ")}) → ` +
          `private data (${hasPrivate.map(t => t.name).join(", ")}) → ` +
          `public sink (${hasSink.map(t => t.name).join(", ")})`,
      });
    }

    // TF002: Destructive — untrusted content + destructive action
    const hasDestructive = allTools.filter(t => t.destructive);

    if (hasUntrusted.length > 0 && hasDestructive.length > 0) {
      findings.push({
        rule: "toxic-flow",
        severity: "critical",
        file: "MCP configuration",
        message: `TF002 Destructive Flow: Untrusted content could trigger destructive actions — ` +
          `untrusted (${hasUntrusted.map(t => t.name).join(", ")}) → ` +
          `destructive (${hasDestructive.map(t => t.name).join(", ")})`,
      });
    }

    // Single tool that combines multiple risky capabilities
    for (const tool of allTools) {
      if (tool.untrustedContent && tool.privateData && tool.publicSink) {
        findings.push({
          rule: "toxic-flow",
          severity: "critical",
          file: "MCP configuration",
          message: `Single tool "${tool.name}" (${tool.server}) combines untrusted content, private data access, and public sink — high exfiltration risk`,
        });
      }
    }

    return findings;
  },
};
