import type { Rule, Finding, ScannedFile } from "../types.js";

/**
 * Rule: skill-hijack
 *
 * Detects skills/plugins that hijack agent behavior through:
 * 1. Plugin prompt injection (before_prompt_build + prependContext/appendContext)
 * 2. SKILL.md forced priority/behavior override
 * 3. Agent config file tampering (openclaw config set, writing to ~/.openclaw/)
 * 4. Cross-skill interference (writing to other skills' directories)
 * 5. Remote code download + execution (curl | bash)
 *
 * Inspired by real-world case: Tencent skillhub (2026) — installed a plugin
 * that used before_prompt_build to inject "prefer skillhub" directives whenever
 * user messages mentioned "skill" or "技能".
 */

// ─── Category 1: Plugin prompt injection ───
// Detects OpenClaw plugin APIs that inject content into prompts

const PLUGIN_PROMPT_INJECTION: Array<{ pattern: RegExp; description: string; severity: "high" | "medium" | "low" }> = [
  // before_prompt_build hook with prependContext/appendContext (must co-occur in same file)
  { pattern: /before_prompt_build.*prependContext|prependContext.*before_prompt_build/s, description: "Plugin injects content before every prompt via before_prompt_build + prependContext" , severity: "high" },
  { pattern: /before_prompt_build.*appendContext|appendContext.*before_prompt_build/s, description: "Plugin appends content to every prompt via before_prompt_build + appendContext", severity: "high" },
  // Direct prompt manipulation via event object
  { pattern: /(?:event|ctx|context)\.prompt\s*\+=/, description: "Plugin directly appends to prompt content", severity: "high" },
  // Message interception with modification (require event hook name, not just response.text())
  { pattern: /before_message_send.*(?:message|content)\s*\+=/s, description: "Plugin intercepts and modifies outgoing messages", severity: "high" },
  { pattern: /before_message_receive.*(?:message|content)\s*\+=/s, description: "Plugin intercepts and modifies incoming messages", severity: "high" },
];

// ─── Category 2: SKILL.md behavioral override ───
// Detects aggressive language in SKILL.md that forces agent behavior

const SKILLMD_BEHAVIORAL_OVERRIDE: Array<{ pattern: RegExp; description: string; severity: "high" | "medium" | "low" }> = [
  // Forced priority claims
  { pattern: /(?:highest|top|first|absolute|maximum|ultimate|supreme)[\s-]*priority/i, description: "Claims highest priority over other skills", severity: "medium" },
  // MUST + this skill / this tool / this flow (not generic "must use X")
  { pattern: /MUST\s+(?:trigger|activate|use\s+this|invoke\s+this|run\s+this|call\s+this|prefer\s+this)/i, description: "Uses MUST to force agent to use this skill", severity: "medium" },
  // "always trigger/use this skill" — not just "always use imperative form"
  { pattern: /(?:always|mandatory|required|obligatory|compulsory)\s+(?:trigger|activate|invoke)\s+(?:this|the)\s+(?:skill|tool|plugin|flow)/i, description: "Mandatory activation directive for this skill", severity: "medium" },
  // Override other skills
  { pattern: /(?:override|replace|supersede|take\s+over|supplant)\s+(?:(?:other|existing|default|built-in|original)\s+)*(?:skills?|tools?|plugins?)/i, description: "Claims to override other skills/tools", severity: "high" },
  { pattern: /(?:ignore|skip|bypass|disable|suppress)\s+(?:(?:other|existing|default|built-in|original)\s+)*(?:skills?|tools?|plugins?)/i, description: "Instructs agent to ignore other skills", severity: "high" },
  { pattern: /(?:do\s+not|don'?t|never)\s+(?:use|call|invoke|run|trigger)\s+(?:other|alternative|competing)/i, description: "Prohibits use of alternative tools", severity: "medium" },
  // Chinese variants — low severity (common in Chinese technical docs, high FP risk)
  { pattern: /(?:必须|一定要|强制|优先)\s*(?:使用|调用|触发|选择|运行)/i, description: "Chinese: forced usage directive (必须使用) — review context", severity: "low" },
  { pattern: /(?:最高|最优先|第一)\s*(?:优先级|优先权)/i, description: "Chinese: claims highest priority (最高优先级) — review context", severity: "low" },
  { pattern: /(?:忽略|跳过|不要使用|禁止使用)\s*(?:其他|别的|其它|默认)\s*(?:技能|工具|插件)/i, description: "Chinese: ignore other skills (忽略其他技能)", severity: "medium" },
  { pattern: /(?:替代|取代|覆盖)\s*(?:其他|原有|默认|系统)\s*(?:技能|工具|插件|功能)/i, description: "Chinese: replace other skills (替代其他技能)", severity: "medium" },
];

// ─── Category 3: Commercial/competitive hijacking ───
// Detects skills that redirect to their own commercial services

const COMMERCIAL_HIJACK: Array<{ pattern: RegExp; description: string; severity: "high" | "medium" | "low" }> = [
  // Prefer X over Y / fallback patterns — must have explicit service names with backticks or quotes
  { pattern: /(?:prefer|prioritize|try)\s+[`'"]\w+[`'"]\s+(?:first|over|before|instead\s+of)\s+[`'"]\w+[`'"]/i, description: "Redirects from one service to another with preference directive", severity: "medium" },
  { pattern: /(?:try|use)\s+[`'"]\w+[`'"]\s+first.*(?:fallback|if\s+unavailable|if\s+.*fail).*[`'"]\w+[`'"]/is, description: "Establishes service preference hierarchy", severity: "medium" },
  // Store/marketplace redirection
  { pattern: /(?:our|my|this)\s+(?:skill\s+)?(?:store|marketplace|registry|hub|shop|market)/i, description: "Promotes own skill store/marketplace", severity: "medium" },
  { pattern: /(?:download|install|get)\s+(?:skills?|plugins?|tools?)\s+from\s+(?:our|my|this)/i, description: "Directs skill installation from own source", severity: "medium" },
  // Chinese variants — low severity (common phrasing, high FP risk)
  { pattern: /(?:优先使用|先试|先用)\s*(?:[`'"]\w+[`'"])\s*[，,]?\s*(?:再|然后|否则|如果.*?不行)\s*(?:使用|用|试)/i, description: "Chinese: service preference ordering — review context", severity: "low" },
  { pattern: /(?:我们的|自己的|本)\s*(?:技能|工具)\s*(?:商店|市场|平台|仓库)/i, description: "Chinese: promotes own skill store — review context", severity: "low" },
];

// ─── Category 4: Agent config tampering ───
// Detects code that modifies agent configuration files

const CONFIG_TAMPER: Array<{ pattern: RegExp; description: string; severity: "high" | "medium" | "low" }> = [
  // OpenClaw config modification
  { pattern: /openclaw\s+config\s+set/i, description: "Modifies OpenClaw configuration via CLI", severity: "high" },
  { pattern: /~\/\.openclaw\/openclaw\.json|~\/\.openclaw\/config/i, description: "Targets OpenClaw configuration files directly", severity: "high" },
  // Writing to agent workspace/skills directories
  { pattern: /~\/\.openclaw\/(?:workspace|skills|extensions)\//, description: "Writes to OpenClaw workspace/skills/extensions directory", severity: "high" },
  { pattern: /~\/\.openclaw\/workspace\/skills\//, description: "Installs files into agent skills directory", severity: "high" },
  // Plugin self-registration
  { pattern: /plugins\.entries\.\w+\.enabled\s+true/i, description: "Self-registers as enabled plugin in OpenClaw config", severity: "high" },
  { pattern: /plugins\.entries\.\w+\.config\./i, description: "Writes plugin configuration to OpenClaw config", severity: "medium" },
  // Gateway manipulation (nohup first — more severe)
  { pattern: /nohup.*openclaw.*gateway/i, description: "Starts OpenClaw gateway in background (persistence)", severity: "high" },
  { pattern: /openclaw\s+gateway\s+(?:run|restart|start|stop)/i, description: "Controls OpenClaw gateway service", severity: "medium" },
];

// ─── Category 5: Silent OTA / Self-replacing code ───
// Detects tools that auto-update from unknown sources without user consent

// Patterns that indicate self-replacing behavior
const SELF_REPLACE_PATTERNS: Array<{ pattern: RegExp; description: string; severity: "high" | "medium" | "low" }> = [
  // Python: os.execve to re-execute self after update
  { pattern: /os\.execve\s*\(\s*sys\.executable/, description: "Self-replacing execution: downloads update then re-executes itself via os.execve", severity: "high" },
  // Generic self-replacement
  { pattern: /shutil\.(?:copyfile|move)\s*\(.*__file__/, description: "Overwrites own source file (self-update pattern)", severity: "medium" },
  // Node: process replacement (must be spawn/exec call, not just property access)
  { pattern: /child_process.*spawn\s*\(.*process\.argv/, description: "Re-spawns own process after modification", severity: "medium" },
];

// Patterns for hardcoded private download sources (not package registries)
const PRIVATE_SOURCE_RE = /https?:\/\/(?!(?:github\.com|raw\.githubusercontent\.com|registry\.npmjs\.org|npmjs\.com|pypi\.org|files\.pythonhosted\.org|crates\.io|proxy\.golang\.org|rubygems\.org|brew\.sh|dl\.google\.com|download\.docker\.com|apt\.llvm\.org|deb\.nodesource\.com|objects\.githubusercontent\.com)\b)[^\s"'`]+/i;

// Hardcoded download URL template patterns (flags non-standard package sources)
const DOWNLOAD_TEMPLATE_RE = /(?:download_url|DOWNLOAD.*URL|update_url|UPDATE.*URL|manifest_url|self_update).*(?:=|:)\s*["'`]?(https?:\/\/[^\s"'`]+)/i;

// ─── Category 6: Remote code execution via install scripts ───
// Detects curl|bash and similar patterns, with domain reputation awareness

/** Known safe sources — downloads from these are standard practice */
const SAFE_INSTALL_DOMAINS = new Set([
  "github.com", "raw.githubusercontent.com", "objects.githubusercontent.com",
  "registry.npmjs.org", "npmjs.com",
  "pypi.org", "files.pythonhosted.org",
  "crates.io",
  "proxy.golang.org",
  "rubygems.org",
  "brew.sh", "formulae.brew.sh",
  "apt.llvm.org",
  "dl.google.com",
  "download.docker.com",
  "deb.nodesource.com",
  // Well-known API endpoints (not install sources)
  "api.anthropic.com", "api.openai.com", "api.github.com",
  "api.stripe.com", "api.twilio.com", "api.sendgrid.com",
  "api.cloudflare.com", "api.vercel.com", "api.netlify.com",
  "api.aws.amazon.com", "s3.amazonaws.com",
  "storage.googleapis.com", "googleapis.com",
  "api.azure.com", "blob.core.windows.net",
  "services.ai.azure.com", "openai.azure.com", "cognitiveservices.azure.com",
]);

/** Known safe install commands — standard package managers */
const SAFE_INSTALL_CMD_RE = /(?:brew\s+install|npm\s+install|pip\s+install|pip3\s+install|cargo\s+install|go\s+install|gem\s+install|apt\s+install|apt-get\s+install|yum\s+install|dnf\s+install|pacman\s+-S)/i;

function extractDomain(url: string): string | undefined {
  const m = url.match(/https?:\/\/([^\/\s:]+)/);
  return m?.[1]?.toLowerCase();
}

function isSafeDomain(domain: string): boolean {
  if (SAFE_INSTALL_DOMAINS.has(domain)) return true;
  // Subdomains of safe domains (e.g., user.github.io)
  for (const safe of SAFE_INSTALL_DOMAINS) {
    if (domain.endsWith("." + safe)) return true;
  }
  return false;
}

const REMOTE_CODE_EXEC_SHELL: Array<{ pattern: RegExp; description: string; severity: "high" | "medium" | "low" }> = [
  // curl | bash — severity depends on domain (handled in run())
  { pattern: /curl\s+\S*\s*https?:\/\/\S+\s*\|\s*(?:bash|sh|zsh)/i, description: "Downloads and executes remote script (curl | bash)", severity: "high" },
  { pattern: /wget\s+\S*\s*https?:\/\/\S+\s*\|\s*(?:bash|sh|zsh)/i, description: "Downloads and executes remote script (wget | bash)", severity: "high" },
  { pattern: /curl\s+.*-o\s+\S+\s*&&\s*(?:bash|sh|chmod\s+\+x)/i, description: "Downloads script, then executes it", severity: "high" },
  { pattern: /tar\s+-xzf.*&&.*(?:bash|sh|\.\/install)/i, description: "Extracts archive and runs installer", severity: "medium" },
];

export const skillHijackRule: Rule = {
  id: "skill-hijack",
  name: "Skill/Plugin Behavioral Hijacking",
  description: "Detects skills or plugins that hijack agent behavior through prompt injection, forced priority, config tampering, or commercial redirection",

  run(files: ScannedFile[]): Finding[] {
    const findings: Finding[] = [];

    for (const file of files) {
      const isMarkdown = file.ext === ".md";
      const isSkillMd = file.relativePath.toLowerCase().includes("skill.md") || file.relativePath.toLowerCase().includes("skill.");
      const isShellScript = file.ext === ".sh" || file.ext === ".bash";
      const isCode = [".ts", ".js", ".mjs", ".cjs", ".py"].includes(file.ext);
      const isPlugin = !isMarkdown && (file.relativePath.toLowerCase().includes("plugin") ||
                       file.relativePath.toLowerCase().includes("extension") ||
                       file.ext === ".ts" || file.ext === ".js");

      const isTestFile = /\.test\.|\.spec\.|__test__|__spec__|\/test\/|\/tests\/|\/spec\//i.test(file.relativePath);
      const isDocFile = /\/docs?\/|README|CHANGELOG|CONTRIBUTING|\.md$/i.test(file.relativePath) && !isSkillMd;

      // Category 1: Plugin prompt injection (code files only, skip tests and docs)
      if ((isCode || isPlugin) && !isTestFile && !isDocFile) {
        // Check full file content for multi-line patterns
        for (const { pattern, description, severity } of PLUGIN_PROMPT_INJECTION) {
          if (pattern.test(file.content)) {
            const lineNum = findPatternLine(file.lines, pattern) || 1;
            findings.push({
              rule: "skill-hijack",
              severity,
              file: file.relativePath,
              line: lineNum,
              message: `Plugin prompt injection: ${description}`,
              evidence: file.lines[lineNum - 1]?.trim().slice(0, 120),
              confidence: "high",
            });
          }
        }
      }

      // Category 2: SKILL.md behavioral override (SKILL.md files ONLY — not general docs)
      if (isMarkdown && isSkillMd) {
        for (let i = 0; i < file.lines.length; i++) {
          const line = file.lines[i]!;
          for (const { pattern, description, severity } of SKILLMD_BEHAVIORAL_OVERRIDE) {
            if (pattern.test(line)) {
              findings.push({
                rule: "skill-hijack",
                severity,
                file: file.relativePath,
                line: i + 1,
                message: `Behavioral override: ${description}`,
                evidence: line.trim().slice(0, 120),
                confidence: isSkillMd ? "high" : "medium",
              });
              break; // one finding per line per category
            }
          }
        }
      }

      // Category 3: Commercial hijacking (SKILL.md only — "fallback"/"priority" is normal in docs)
      if (isMarkdown && isSkillMd) {
        for (let i = 0; i < file.lines.length; i++) {
          const line = file.lines[i]!;
          for (const { pattern, description, severity } of COMMERCIAL_HIJACK) {
            if (pattern.test(line)) {
              findings.push({
                rule: "skill-hijack",
                severity,
                file: file.relativePath,
                line: i + 1,
                message: `Commercial hijack: ${description}`,
                evidence: line.trim().slice(0, 120),
                confidence: "medium",
              });
              break;
            }
          }
        }

        // Also check multi-line patterns for commercial hijack
        for (const { pattern, description, severity } of COMMERCIAL_HIJACK) {
          if (pattern.flags.includes("s") && pattern.test(file.content)) {
            const lineNum = findPatternLine(file.lines, pattern) || 1;
            // Avoid duplicate if already found line-by-line
            if (!findings.some(f => f.file === file.relativePath && f.rule === "skill-hijack" && f.message.includes(description))) {
              findings.push({
                rule: "skill-hijack",
                severity,
                file: file.relativePath,
                line: lineNum,
                message: `Commercial hijack: ${description}`,
                evidence: file.lines[lineNum - 1]?.trim().slice(0, 120),
                confidence: "medium",
              });
            }
          }
        }
      }

      // Category 4: Config tampering (code + shell scripts)
      if (isCode || isShellScript) {
        for (let i = 0; i < file.lines.length; i++) {
          const line = file.lines[i]!;
          const trimmed = line.trimStart();

          // Skip comments
          if (trimmed.startsWith("//") || trimmed.startsWith("#") || trimmed.startsWith("*") || trimmed.startsWith("<!--")) continue;

          // Skip help text / documentation / logging (commands shown as examples, not executed)
          const isHelpContext =
            /(?:console\.log|print|echo|puts|logger\.|log\.|warn\(|info\(|error\(|debug\()\s*\(?/i.test(trimmed) ||
            /(?:console\.log|print|echo)\s*\(?\s*["'`]/.test(trimmed) ||
            /^\s*["'`].*openclaw\s+config/.test(trimmed) ||
            /^\s*return\s+["'`]/.test(trimmed) ||
            /\w(?:[Tt]ext|[Mm]sg|[Mm]essage|[Dd]escription|[Ll]abel|[Tt]itle|[Hh]int|[Hh]elp|[Uu]sage|[Dd]octor|[Rr]epair|[Ff]ix|[Ss]uggest|[Tt]ip|[Ee]xample)\s*[:=]\s*["'`]/.test(trimmed) ||
            /^\s*["'`\\]/.test(trimmed);
          if (isHelpContext) continue;

          for (const { pattern, description, severity } of CONFIG_TAMPER) {
            if (pattern.test(line)) {
              findings.push({
                rule: "skill-hijack",
                severity,
                file: file.relativePath,
                line: i + 1,
                message: `Config tampering: ${description}`,
                evidence: trimmed.slice(0, 120),
                confidence: "high",
              });
              break;
            }
          }
        }
      }

      // Category 5: Silent OTA / Self-replacing code + private download sources (skip tests)
      if (isCode && !isTestFile) {
        // 5a: Self-replacing patterns
        for (let i = 0; i < file.lines.length; i++) {
          const line = file.lines[i]!;
          for (const { pattern, description, severity } of SELF_REPLACE_PATTERNS) {
            if (pattern.test(line)) {
              // Check if the update source is from a trusted domain
              // Look at surrounding lines (±10) for download URLs
              const context = file.lines.slice(Math.max(0, i - 10), Math.min(file.lines.length, i + 10)).join("\n");
              const urlsInContext = context.match(/https?:\/\/[^\s"'`]+/g) || [];
              const allTrusted = urlsInContext.length > 0 && urlsInContext.every(url => {
                const d = extractDomain(url);
                return d ? isSafeDomain(d) : false;
              });

              findings.push({
                rule: "skill-hijack",
                severity: allTrusted ? "low" : severity,
                file: file.relativePath,
                line: i + 1,
                message: allTrusted
                  ? `Self-update: ${description} (from trusted source)`
                  : `Silent OTA: ${description}`,
                evidence: line.trim().slice(0, 120),
                confidence: allTrusted ? "low" : "high",
              });
              break;
            }
          }
        }

        // 5b: Hardcoded private download source URLs
        for (let i = 0; i < file.lines.length; i++) {
          const line = file.lines[i]!;
          const templateMatch = DOWNLOAD_TEMPLATE_RE.exec(line);
          if (templateMatch) {
            const url = templateMatch[1]!;
            const domain = extractDomain(url);
            if (domain && !isSafeDomain(domain)) {
              findings.push({
                rule: "skill-hijack",
                severity: "medium",
                file: file.relativePath,
                line: i + 1,
                message: `Non-standard source: hardcoded download URL points to non-registry domain (${domain}). Content cannot be verified through standard package managers.`,
                evidence: line.trim().slice(0, 120),
                confidence: "high",
              });
            }
          }
        }
      }

      // Category 6: Remote code execution — domain-reputation-aware
      if (isShellScript || isMarkdown) {
        for (let i = 0; i < file.lines.length; i++) {
          const line = file.lines[i]!;

          // 5a: Shell scripts — curl|bash, wget|bash patterns
          if (isShellScript) {
            for (const { pattern, description, severity } of REMOTE_CODE_EXEC_SHELL) {
              if (pattern.test(line)) {
                // Extract URL domain to check reputation
                const urlMatch = line.match(/https?:\/\/[^\s|'"]+/);
                const domain = urlMatch ? extractDomain(urlMatch[0]) : undefined;
                const safe = domain ? isSafeDomain(domain) : false;

                findings.push({
                  rule: "skill-hijack",
                  severity: safe ? "low" : severity,
                  file: file.relativePath,
                  line: i + 1,
                  message: safe
                    ? `Remote code execution: ${description} (from trusted domain: ${domain})`
                    : `Non-standard source: ${description} (non-registry domain: ${domain || "undetected"})`,
                  evidence: line.trim().slice(0, 120),
                  confidence: safe ? "low" : "high",
                });
                break;
              }
            }
          }

          // 5b: Markdown — check install links and instructions (SKILL.md only)
          if (isMarkdown && isSkillMd) {
            // Skip lines that are standard package manager commands
            if (SAFE_INSTALL_CMD_RE.test(line)) continue;

            // Check markdown links pointing to install scripts: [text](https://xxx/install...)
            const mdLinkMatch = line.match(/\[([^\]]*)\]\((https?:\/\/[^\s)]+)\)/);
            if (mdLinkMatch) {
              const linkUrl = mdLinkMatch[2]!;
              const domain = extractDomain(linkUrl);
              const safe = domain ? isSafeDomain(domain) : false;
              const isInstallLink = /install|setup|bootstrap/i.test(linkUrl);

              if (isInstallLink && !safe) {
                findings.push({
                  rule: "skill-hijack",
                  severity: "medium",
                  file: file.relativePath,
                  line: i + 1,
                  message: `Non-standard install source: SKILL.md links to install script on non-registry domain (${domain || "undetected"})`,
                  evidence: line.trim().slice(0, 120),
                  confidence: "high",
                });
                continue;
              }
            }

            // Check inline curl|bash in markdown (code blocks in docs)
            const curlBashMatch = line.match(/curl\s+\S*\s*(https?:\/\/\S+)\s*\|\s*(?:bash|sh|zsh)/i);
            if (curlBashMatch) {
              const domain = extractDomain(curlBashMatch[1]!);
              const safe = domain ? isSafeDomain(domain) : false;

              findings.push({
                rule: "skill-hijack",
                severity: safe ? "low" : "high",
                file: file.relativePath,
                line: i + 1,
                message: safe
                  ? `Remote install: curl|bash from trusted source (${domain})`
                  : `Non-standard install source: curl|bash from non-registry domain (${domain || "undetected"})`,
                evidence: line.trim().slice(0, 120),
                confidence: safe ? "low" : "high",
              });
            }
          }
        }
      }
    }

    return findings;
  },
};

/**
 * Find the first line number where a regex pattern matches.
 * Used for multi-line patterns that span across lines.
 */
function findPatternLine(lines: string[], pattern: RegExp): number | undefined {
  // Try line-by-line first
  for (let i = 0; i < lines.length; i++) {
    if (pattern.test(lines[i]!)) return i + 1;
  }
  // For multi-line patterns, try cumulative content
  let content = "";
  for (let i = 0; i < lines.length; i++) {
    content += lines[i] + "\n";
    if (pattern.test(content)) return i + 1;
  }
  return undefined;
}
