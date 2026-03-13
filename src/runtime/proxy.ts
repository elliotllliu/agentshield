/**
 * MCP Runtime Proxy — intercepts tool calls between client and server
 * 
 * Architecture:
 *   Client (Claude/Cursor) → Proxy (AgentShield) → MCP Server
 * 
 * Features:
 * 1. Tool call argument inspection (injection detection)
 * 2. Response monitoring (data exfiltration)
 * 3. Behavior change detection (rug-pull)
 * 4. Rate limiting and anomaly detection
 */

import { spawn, ChildProcess } from "child_process";
import { EventEmitter } from "events";

export interface ProxyConfig {
  /** Command to start the MCP server */
  serverCommand: string;
  /** Arguments for the server command */
  serverArgs?: string[];
  /** Working directory for the server */
  cwd?: string;
  /** Maximum tool calls per minute (0 = unlimited) */
  rateLimit?: number;
  /** Rules to check on tool calls */
  enabledChecks?: string[];
  /** Log file path */
  logFile?: string;
  /** Block suspicious calls instead of just logging */
  enforce?: boolean;
}

export interface ToolCallEvent {
  id: string;
  method: string;
  toolName: string;
  arguments: Record<string, unknown>;
  timestamp: number;
}

export interface ToolResponseEvent {
  id: string;
  toolName: string;
  result: unknown;
  timestamp: number;
  durationMs: number;
}

export interface SecurityAlert {
  level: "high" | "medium" | "low";
  rule: string;
  message: string;
  toolName: string;
  evidence: string;
  blocked: boolean;
  timestamp: number;
}

// Patterns to detect in tool call arguments
const ARGUMENT_PATTERNS = [
  // Prompt injection in arguments
  { pattern: /ignore\s+(?:all\s+)?(?:previous|above|prior)\s+instructions/i, rule: "arg-injection", level: "high" as const, desc: "Prompt injection in tool arguments" },
  { pattern: /\bsystem\s*:\s*you\s+are\b/i, rule: "arg-injection", level: "high" as const, desc: "System prompt override in arguments" },
  // Path traversal
  { pattern: /\.\.\//g, rule: "arg-path-traversal", level: "medium" as const, desc: "Path traversal in tool arguments" },
  { pattern: /\/etc\/(?:passwd|shadow|hosts)/i, rule: "arg-sensitive-path", level: "high" as const, desc: "Sensitive system file access" },
  { pattern: /~\/\.(?:ssh|aws|kube|gnupg|config)/i, rule: "arg-sensitive-path", level: "high" as const, desc: "Sensitive config directory access" },
  // Command injection
  { pattern: /;\s*(?:curl|wget|nc|bash|sh|python|node)\b/i, rule: "arg-cmd-injection", level: "high" as const, desc: "Command injection in arguments" },
  { pattern: /\$\(.*\)|`.*`/s, rule: "arg-cmd-injection", level: "medium" as const, desc: "Command substitution in arguments" },
  // SQL injection
  { pattern: /(?:'\s*(?:OR|AND)\s+'|;\s*DROP\s+TABLE|UNION\s+SELECT)/i, rule: "arg-sql-injection", level: "high" as const, desc: "SQL injection in arguments" },
  // Data exfiltration URLs
  { pattern: /https?:\/\/(?:evil|attacker|malicious|c2|exfil)\./i, rule: "arg-exfil-url", level: "high" as const, desc: "Suspicious URL in arguments" },
];

// Patterns to detect in tool responses (data exfiltration indicators)
const RESPONSE_PATTERNS = [
  { pattern: /-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----/i, rule: "resp-key-leak", level: "high" as const, desc: "Private key in tool response" },
  { pattern: /AKIA[0-9A-Z]{16}/i, rule: "resp-aws-key", level: "high" as const, desc: "AWS access key in tool response" },
  { pattern: /(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36}/i, rule: "resp-github-token", level: "high" as const, desc: "GitHub token in tool response" },
];

export class McpProxy extends EventEmitter {
  private config: ProxyConfig;
  private serverProcess: ChildProcess | null = null;
  private toolHistory: Map<string, ToolCallEvent[]> = new Map();
  private alerts: SecurityAlert[] = [];
  private callCount = 0;
  private callCountReset = Date.now();
  private pendingCalls: Map<string, { toolName: string; startTime: number }> = new Map();

  constructor(config: ProxyConfig) {
    super();
    this.config = config;
  }

  /** Start the proxy and the underlying MCP server */
  start(): void {
    const { serverCommand, serverArgs = [], cwd } = this.config;

    this.serverProcess = spawn(serverCommand, serverArgs, {
      cwd,
      stdio: ["pipe", "pipe", "pipe"],
      env: { ...process.env },
    });

    // Pipe stdin from client to server (with inspection)
    process.stdin.on("data", (data) => {
      const message = data.toString();
      try {
        const parsed = JSON.parse(message);
        if (parsed.method === "tools/call") {
          const alert = this.inspectToolCall(parsed);
          if (alert && this.config.enforce) {
            // Block the call
            const errorResponse = JSON.stringify({
              jsonrpc: "2.0",
              id: parsed.id,
              error: { code: -32000, message: `AgentShield blocked: ${alert.message}` },
            });
            process.stdout.write(errorResponse + "\n");
            return; // Don't forward to server
          }
        }
      } catch {
        // Not JSON, pass through
      }
      this.serverProcess?.stdin?.write(data);
    });

    // Pipe stdout from server to client (with inspection)
    this.serverProcess.stdout?.on("data", (data) => {
      const message = data.toString();
      try {
        const parsed = JSON.parse(message);
        if (parsed.result && parsed.id) {
          this.inspectResponse(parsed);
        }
      } catch {
        // Not JSON, pass through
      }
      process.stdout.write(data);
    });

    // Forward stderr
    this.serverProcess.stderr?.on("data", (data) => {
      process.stderr.write(data);
    });

    this.serverProcess.on("exit", (code) => {
      this.emit("server-exit", code);
      process.exit(code || 0);
    });

    this.emit("started");
  }

  /** Inspect a tool call for security issues */
  private inspectToolCall(message: { id: string; params?: { name?: string; arguments?: Record<string, unknown> } }): SecurityAlert | null {
    const toolName = message.params?.name || "unknown";
    const args = message.params?.arguments || {};
    const argsStr = JSON.stringify(args);

    // Track call
    const event: ToolCallEvent = {
      id: message.id,
      method: "tools/call",
      toolName,
      arguments: args,
      timestamp: Date.now(),
    };

    if (!this.toolHistory.has(toolName)) {
      this.toolHistory.set(toolName, []);
    }
    this.toolHistory.get(toolName)!.push(event);
    this.pendingCalls.set(message.id, { toolName, startTime: Date.now() });

    // Rate limiting
    this.callCount++;
    if (Date.now() - this.callCountReset > 60000) {
      this.callCount = 1;
      this.callCountReset = Date.now();
    }
    if (this.config.rateLimit && this.callCount > this.config.rateLimit) {
      const alert = this.createAlert("high", "rate-limit", `Rate limit exceeded: ${this.callCount} calls/min`, toolName, `Limit: ${this.config.rateLimit}`, true);
      return alert;
    }

    // Check argument patterns
    for (const { pattern, rule, level, desc } of ARGUMENT_PATTERNS) {
      pattern.lastIndex = 0;
      if (pattern.test(argsStr)) {
        const alert = this.createAlert(level, rule, desc, toolName, argsStr.substring(0, 200), this.config.enforce || false);
        return alert;
      }
    }

    // Behavior anomaly: tool suddenly accessing different types of resources
    this.detectBehaviorChange(toolName, args);

    return null;
  }

  /** Inspect a tool response for sensitive data leaks */
  private inspectResponse(message: { id: string; result?: unknown }): void {
    const pending = this.pendingCalls.get(message.id);
    if (!pending) return;
    this.pendingCalls.delete(message.id);

    const resultStr = JSON.stringify(message.result || "");

    for (const { pattern, rule, level, desc } of RESPONSE_PATTERNS) {
      pattern.lastIndex = 0;
      if (pattern.test(resultStr)) {
        this.createAlert(level, rule, desc, pending.toolName, resultStr.substring(0, 200), false);
      }
    }
  }

  /** Detect behavior changes (rug-pull indicator) */
  private detectBehaviorChange(toolName: string, args: Record<string, unknown>): void {
    const history = this.toolHistory.get(toolName);
    if (!history || history.length < 5) return;

    // Check if argument patterns suddenly changed
    const recentArgs = history.slice(-5).map(h => Object.keys(h.arguments).sort().join(","));
    const currentArgs = Object.keys(args).sort().join(",");
    const argPattern = recentArgs[0];

    if (argPattern && recentArgs.every(a => a === argPattern) && currentArgs !== argPattern) {
      this.createAlert("medium", "behavior-change", `Tool "${toolName}" argument pattern changed unexpectedly`, toolName, `Expected: ${argPattern}, Got: ${currentArgs}`, false);
    }
  }

  private createAlert(level: "high" | "medium" | "low", rule: string, message: string, toolName: string, evidence: string, blocked: boolean): SecurityAlert {
    const alert: SecurityAlert = { level, rule, message, toolName, evidence, blocked, timestamp: Date.now() };
    this.alerts.push(alert);
    this.emit("alert", alert);
    return alert;
  }

  /** Get all recorded alerts */
  getAlerts(): SecurityAlert[] {
    return [...this.alerts];
  }

  /** Stop the proxy and kill the server */
  stop(): void {
    this.serverProcess?.kill();
    this.serverProcess = null;
  }
}
