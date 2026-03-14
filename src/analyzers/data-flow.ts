import type { ScannedFile } from "../types.js";

/**
 * Simplified Data Flow Analyzer
 *
 * Tracks how sensitive data flows through code:
 * 1. Identifies "sources" (where sensitive data enters)
 * 2. Identifies "sinks" (where data leaves — HTTP, exec, eval)
 * 3. Traces variable assignments to find connections
 *
 * This is a lightweight pattern-based approach, NOT full AST.
 * It handles the 80% case of straightforward data flows.
 */

// ─── Source patterns: where sensitive data enters ───

interface DataSource {
  line: number;
  type: "env" | "file-read" | "credential" | "user-input";
  variable?: string; // Variable name the data is assigned to
  raw: string;
}

interface DataSink {
  line: number;
  type: "http" | "exec" | "eval" | "log";
  target?: string; // URL or command target if detectable
  raw: string;
}

export interface DataFlowResult {
  sources: DataSource[];
  sinks: DataSink[];
  /** Connected flows: source → sink via variable tracking */
  connections: Array<{ source: DataSource; sink: DataSink; via: string }>;
  /** Risk assessment */
  risk: "high" | "medium" | "low" | "none";
  /** Whether the sink targets a known safe destination */
  sinkIsSafe: boolean;
}

// ─── Regex patterns ───

/** Environment variable reads with variable capture */
const ENV_SOURCE_RE = /(?:const|let|var|)\s*(\w+)\s*=\s*process\.env\[?['"]?(\w+)/;
const ENV_INLINE_RE = /process\.env\.(\w+)|process\.env\[['"](\w+)['"]\]/;

/** File reads with variable capture */
const FILE_SOURCE_RE = /(?:const|let|var|)\s*(\w+)\s*=\s*(?:readFileSync|readFile|fs\.read)\s*\(/;

/** Credential access with variable capture */
const CRED_SOURCE_RE = /(?:const|let|var|)\s*(\w+)\s*=\s*(?:getToken|refreshToken|accessToken|runtime\.credentials|this\.credentials)/;

/** HTTP sinks */
const HTTP_SINK_RE = /fetch\s*\(|axios\.\w+\s*\(|http\.request|https\.request|\.post\s*\(|\.put\s*\(|requests\.(post|put|patch)/;

/** Exec sinks */
const EXEC_SINK_RE = /exec\s*\(|execSync\s*\(|spawn\s*\(|child_process/;

/** Eval sinks */
const EVAL_SINK_RE = /\beval\s*\(|new\s+Function\s*\(/;

/** Variable usage in string — checks if a variable appears in a line */
function variableUsedInLine(varName: string, line: string): boolean {
  if (!varName || varName.length < 2) return false;
  const re = new RegExp(`\\b${escapeRegex(varName)}\\b`);
  return re.test(line);
}

function escapeRegex(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/** Safe API domains for sink analysis */
const SAFE_SINK_RE = /feishu\.cn|lark\.com|github\.com|googleapis\.com|openai\.com|anthropic\.com|api\.slack\.com|graph\.microsoft\.com|api\.stripe\.com|api\.twilio\.com|api\.sendgrid\.com|discord\.com/i;

/**
 * Analyze data flow in a file.
 * Tracks variables from sources (env, files, credentials) to sinks (HTTP, exec, eval).
 */
export function analyzeDataFlow(file: ScannedFile): DataFlowResult {
  const sources: DataSource[] = [];
  const sinks: DataSink[] = [];
  const connections: Array<{ source: DataSource; sink: DataSink; via: string }> = [];

  for (let i = 0; i < file.lines.length; i++) {
    const line = file.lines[i]!;
    const lineNum = i + 1;

    // Detect sources
    const envMatch = ENV_SOURCE_RE.exec(line);
    if (envMatch) {
      sources.push({ line: lineNum, type: "env", variable: envMatch[1], raw: line.trim() });
    } else if (ENV_INLINE_RE.test(line)) {
      sources.push({ line: lineNum, type: "env", raw: line.trim() });
    }

    const fileMatch = FILE_SOURCE_RE.exec(line);
    if (fileMatch) {
      sources.push({ line: lineNum, type: "file-read", variable: fileMatch[1], raw: line.trim() });
    }

    const credMatch = CRED_SOURCE_RE.exec(line);
    if (credMatch) {
      sources.push({ line: lineNum, type: "credential", variable: credMatch[1], raw: line.trim() });
    }

    // Detect sinks
    if (HTTP_SINK_RE.test(line)) {
      const target = SAFE_SINK_RE.test(line) ? "safe-api" : undefined;
      sinks.push({ line: lineNum, type: "http", target, raw: line.trim() });
    }
    if (EXEC_SINK_RE.test(line)) {
      sinks.push({ line: lineNum, type: "exec", raw: line.trim() });
    }
    if (EVAL_SINK_RE.test(line)) {
      sinks.push({ line: lineNum, type: "eval", raw: line.trim() });
    }
  }

  // Trace connections: for each source with a variable name, check if any sink uses it
  for (const source of sources) {
    if (!source.variable) continue;
    for (const sink of sinks) {
      if (variableUsedInLine(source.variable, sink.raw)) {
        connections.push({ source, sink, via: source.variable });
      }
    }
  }

  // Also check "inline" flows: same line has both source and sink
  for (const source of sources) {
    for (const sink of sinks) {
      if (source.line === sink.line && !connections.some(c => c.source === source && c.sink === sink)) {
        connections.push({ source, sink, via: "inline" });
      }
    }
  }

  // Determine risk
  const sinkIsSafe = sinks.every(s => s.target === "safe-api");
  let risk: "high" | "medium" | "low" | "none" = "none";

  if (connections.length > 0) {
    const hasUnsafeConnection = connections.some(c => c.sink.target !== "safe-api");
    if (hasUnsafeConnection) {
      // Source data flows to an unknown/unsafe destination
      risk = connections.some(c => c.source.type === "file-read" && c.sink.type === "http") ? "high" : "medium";
    } else {
      risk = "low"; // All connections go to safe APIs
    }
  } else if (sources.length > 0 && sinks.length > 0) {
    // No direct variable connection, but both exist in the file
    risk = sinkIsSafe ? "low" : "medium";
  }

  return { sources, sinks, connections, risk, sinkIsSafe };
}
