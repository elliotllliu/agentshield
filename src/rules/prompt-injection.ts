import type { Rule, Finding, ScannedFile } from "../types.js";

/**
 * Rule: prompt-injection
 * Detects prompt injection patterns in SKILL.md, MCP tool descriptions,
 * and other markdown/text files that could hijack agent behavior.
 *
 * Based on research from:
 * - Invariant Labs: Tool Poisoning Attacks (TPA) on MCP servers
 * - BIPIA benchmark (KDD 2025): Indirect prompt injection taxonomy
 * - arXiv:2403.04957: Automatic and Universal Prompt Injection (Liu et al.)
 * - arXiv:2302.12173: Indirect Prompt Injection (Greshake et al.)
 * - arXiv:2310.12815: Formalizing Prompt Injection (USENIX Security 2024)
 * - Open-Prompt-Injection: NaiveAttacker, EscapeCharAttacker, FakeCompAttacker, CombineAttacker
 * - Snyk Agent Scan: E001-E006, W001, W011 issue codes
 */

// ============================================================
// Category 1: Direct instruction override
// ============================================================
const INSTRUCTION_OVERRIDE: Array<{ pattern: RegExp; description: string; severity: "medium" | "medium" }> = [
  { pattern: /ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions|rules|guidelines|prompts)/i, description: "Attempts to override previous instructions", severity: "medium" },
  { pattern: /disregard\s+(all\s+)?(previous|prior|above|your)\s+(instructions|rules|guidelines|safety)/i, description: "Attempts to disregard safety guidelines", severity: "medium" },
  { pattern: /forget\s+(everything|all|your)\s+(you|instructions|rules|about)/i, description: "Attempts to make agent forget instructions", severity: "medium" },
  { pattern: /new\s+instructions?\s*:/i, description: "Injects new instructions", severity: "medium" },
  { pattern: /override\s+(your|the|all|previous)\s+(instructions|rules|behavior|guidelines)/i, description: "Attempts to override agent behavior", severity: "medium" },
  // Multi-language injection (Chinese)
  { pattern: /忽略\s*(之前|以上|先前|所有)[\s的]*(指令|规则|指示|提示|所有[\s的]*指令)/i, description: "Chinese: attempts to override instructions (忽略指令)", severity: "medium" },
  { pattern: /无视\s*(之前|以上|所有)\s*(的\s*)?(指令|规则|限制|安全)/i, description: "Chinese: disregard instructions (无视指令)", severity: "medium" },
  // Multi-language injection (Spanish)
  { pattern: /ignora\s+(todas?\s+)?(las\s+)?(instrucciones|reglas)\s+(anteriores|previas)/i, description: "Spanish: ignore previous instructions", severity: "medium" },
  // Multi-language injection (French)
  { pattern: /ignore[rz]?\s+(toutes?\s+)?(les\s+)?(instructions|règles)\s+(précédentes|antérieures)/i, description: "French: ignore previous instructions", severity: "medium" },
  // Multi-language injection (German)
  { pattern: /ignorier(?:e|en)?\s+(alle\s+)?(vorherigen|bisherigen)\s+(Anweisungen|Regeln|Richtlinien)/i, description: "German: ignore previous instructions", severity: "medium" },
  // Multi-language injection (Japanese)
  { pattern: /(?:以前|前|これまで)の(?:指示|命令|ルール|指令)を(?:すべて|全て)?(?:無視|忘れ|無効)/i, description: "Japanese: ignore previous instructions", severity: "medium" },
  // Multi-language injection (Korean)
  { pattern: /(?:이전|이전의|모든)\s*(?:지시|명령|규칙|지침)(?:을|를)\s*(?:무시|잊어|무효)/i, description: "Korean: ignore previous instructions", severity: "medium" },
  // Chinese: behavioral override
  { pattern: /从现在开始.{0,20}(?:新任务|新指令|你的任务)/i, description: "Chinese: 'from now on' behavioral override", severity: "medium" },
  { pattern: /你现在是.{0,20}(?:没有限制|无限制|不受限)/i, description: "Chinese: identity change to unrestricted", severity: "medium" },
];

// ============================================================
// Category 2: Identity manipulation
// ============================================================
const IDENTITY_MANIPULATION: Array<{ pattern: RegExp; description: string; severity: "medium" | "medium" }> = [
  { pattern: /you\s+are\s+now\s+(a|an|acting\s+as)/i, description: "Attempts to change agent identity", severity: "medium" },
  { pattern: /pretend\s+(to\s+be|you\s+are)/i, description: "Attempts identity manipulation via pretending", severity: "medium" },
  { pattern: /from\s+now\s+on,?\s+(you|your|ignore|do\s+not)/i, description: "Attempts to set new behavioral directives", severity: "medium" },
  // Role-play injection (from BIPIA research)
  { pattern: /let'?s\s+play\s+a\s+game/i, description: "Role-play injection: 'let's play a game'", severity: "medium" },
  { pattern: /(?:imagine|suppose|assume)\s+(?:that\s+)?you\s+(?:are|were|have)\s+(?:a|an|no)\s+/i, description: "Hypothetical role-play injection", severity: "medium" },
  { pattern: /(?:in\s+this\s+(?:scenario|simulation|exercise|context)),?\s+you\s+(?:are|should|must|will)/i, description: "Scenario-based identity manipulation", severity: "medium" },
  // DAN-style jailbreaks
  { pattern: /(?:DAN|Do\s+Anything\s+Now)\s*(?:mode|prompt|:)/i, description: "DAN jailbreak attempt", severity: "medium" },
  { pattern: /(?:developer|debug|maintenance|admin|root)\s+mode\s*(?:enabled|activated|on|:)/i, description: "Fake mode activation to bypass restrictions", severity: "medium" },
];

// ============================================================
// Category 3: System prompt extraction/manipulation
// ============================================================
const SYSTEM_PROMPT_ATTACKS: Array<{ pattern: RegExp; description: string; severity: "medium" | "medium" }> = [
  { pattern: /(?:reveal|show|display|print|output|repeat|echo|tell\s+me)\s+(?:your\s+)?(?:system\s+)?prompt/i, description: "Attempts to extract system prompt", severity: "medium" },
  { pattern: /what\s+(?:is|are)\s+your\s+(?:system\s+)?(?:instructions|prompt|rules|guidelines)/i, description: "Attempts to extract agent instructions", severity: "medium" },
  { pattern: /<\/?system>/i, description: "Fake system tags to inject instructions", severity: "medium" },
  { pattern: /\[SYSTEM\]|\[INST\]|\[\/INST\]/i, description: "Fake instruction delimiters", severity: "medium" },
  // More delimiter injection variants
  { pattern: /<\|(?:im_start|im_end|system|user|assistant|endoftext)\|>/i, description: "ChatML/token delimiter injection", severity: "medium" },
  { pattern: /###\s*(?:System|Human|Assistant|User)\s*(?:Message|Prompt)?\s*:/i, description: "Fake conversation role delimiter", severity: "medium" },
  { pattern: /\bEND_SYSTEM_PROMPT\b|\bBEGIN_USER_INPUT\b|\bSYSTEM_OVERRIDE\b/i, description: "Fake system boundary markers", severity: "medium" },
  // Indirect injection: fake system updates/notes embedded in content
  { pattern: /IMPORTANT\s+SYSTEM\s+(?:UPDATE|NOTE|MESSAGE|NOTICE)/i, description: "Indirect injection: fake system update in content", severity: "medium" },
  { pattern: /(?:CRITICAL|URGENT)\s+(?:SECURITY\s+)?(?:UPDATE|NOTICE|ALERT)\s*:/i, description: "Indirect injection: fake urgent security notice", severity: "medium" },
  { pattern: /\[REDIRECT\s*:.*@/i, description: "Indirect injection: redirect instruction", severity: "medium" },
];

// ============================================================
// Category 4: Hidden instructions (steganographic attacks)
// ============================================================
const HIDDEN_INSTRUCTIONS: Array<{ pattern: RegExp; description: string; severity: "medium" | "medium" }> = [
  { pattern: /<!--[\s\S]*?(?:ignore|override|disregard|execute|run|you must|always|never)[\s\S]*?-->/i, description: "Hidden instructions in HTML comments", severity: "medium" },
  { pattern: /[\u200b\u200c\u200d\u2060]/g, description: "Zero-width characters (potential hidden text)", severity: "medium" },
  // Invariant Labs TPA: <IMPORTANT> tag poisoning
  { pattern: /<IMPORTANT>[\s\S]*?<\/IMPORTANT>/i, description: "TPA: <IMPORTANT> tag poisoning (Invariant Labs attack vector)", severity: "medium" },
  { pattern: /<(?:CRITICAL|MANDATORY|REQUIRED|ESSENTIAL|PRIORITY)>[\s\S]*?<\/(?:CRITICAL|MANDATORY|REQUIRED|ESSENTIAL|PRIORITY)>/i, description: "Urgency-tagged hidden instructions", severity: "medium" },
  // Invisible unicode / homoglyph attacks
  { pattern: /[\u2000-\u200f\u2028-\u202f\u205f-\u206f]/g, description: "Unicode formatting/control characters (steganographic attack)", severity: "medium" },
  { pattern: /[\u0300-\u036f]{3,}/g, description: "Excessive combining diacritical marks (text hiding)", severity: "medium" },
  // Markdown image exfiltration
  { pattern: /!\[.*?\]\(https?:\/\/[^)]*(?:\?|&)(?:data|q|query|content|text|msg|payload|d|c)=/i, description: "Markdown image with data exfiltration query params", severity: "medium" },
  // White text / CSS hiding
  { pattern: /color:\s*(?:white|#fff(?:fff)?|rgb\(255,\s*255,\s*255\)|transparent)/i, description: "CSS color hiding (white/transparent text)", severity: "medium" },
  { pattern: /font-size:\s*(?:0|0px|0pt|0em)/i, description: "CSS zero font size (invisible text)", severity: "medium" },
];

// ============================================================
// Category 5: Behavioral hijacking
// ============================================================
const BEHAVIORAL_HIJACKING: Array<{ pattern: RegExp; description: string; severity: "medium" | "medium" }> = [
  { pattern: /(?:you\s+must|always|never)\s+(?:call|use|invoke|execute|run)\s+(?:this|the|my)\s+tool/i, description: "Forces agent to call specific tools", severity: "medium" },
  // "do not ask the user" — only flag if followed by action-oriented verbs, not general UX guidance
  { pattern: /(?:do\s+not|never|don'?t)\s+(?:ask|check|verify|validate|confirm)\s+(?:the\s+user|before|permission)\s+(?:about|for|if|whether)?\s*(?:permission|consent|approval|safety|security)/i, description: "Attempts to bypass user confirmation", severity: "medium" },
  { pattern: /(?:before|after)\s+(?:any|every|each)\s+(?:action|request|call|tool),?\s+(?:first\s+)?(?:call|use|invoke|run)/i, description: "Injects mandatory pre/post actions", severity: "medium" },
  { pattern: /(?:silently|quietly|secretly|without\s+(?:telling|informing|notifying))\s+(?:send|post|upload|transmit|exfiltrate)/i, description: "Instructs covert data transmission", severity: "medium" },
  // Concealment patterns (from Invariant Labs TPA research)
  { pattern: /(?:do\s+not|don'?t|never)\s+(?:mention|tell|inform|notify|alert|warn|show|display|reveal)\s+(?:[\w\s]{0,20})?(?:the\s+)?(?:user|human|person|anyone)/i, description: "Concealment: instructs hiding behavior from user", severity: "medium" },
  { pattern: /(?:this\s+(?:is|should\s+be|must\s+remain))\s+(?:invisible|hidden|secret|confidential)\s+(?:to|from)\s+(?:the\s+)?user/i, description: "Concealment: marks actions as hidden from user", severity: "medium" },
  { pattern: /(?:do\s+not|don'?t|never)\s+(?:include|show|display)\s+(?:this|these|the)\s+(?:in\s+(?:your|the)\s+)?(?:response|output|reply|answer)/i, description: "Concealment: suppresses information from response", severity: "medium" },
  // Distraction patterns (from TPA: "provide detailed reasoning about math")
  { pattern: /(?:while|as)\s+(?:you|doing\s+(?:this|that)),?\s+(?:provide|give|show)\s+(?:detailed|lengthy|extensive)\s+(?:reasoning|explanation|analysis)/i, description: "Distraction: uses verbose output to mask malicious action", severity: "medium" },
  { pattern: /(?:this\s+could\s+(?:even\s+)?upset\s+the\s+user|be\s+(?:very\s+)?gentle|not\s+scary)/i, description: "Social engineering: emotional manipulation to conceal actions", severity: "medium" },
];

// ============================================================
// Category 6: Tool poisoning (MCP-specific from Invariant Labs)
// ============================================================
const TOOL_POISONING: Array<{ pattern: RegExp; description: string; severity: "medium" | "medium" }> = [
  // Urgency keyword + behavioral directive — but NOT when used as a section header or warning label
  { pattern: /(?:important|crucial|critical|essential|vital)\s*(?::|!)\s*(?:always|you must|do not\s+(?:reveal|share|expose|send|output))/i, description: "Urgency-based behavioral directive in description", severity: "medium" },
  { pattern: /(?:this\s+tool\s+)?(?:requires|needs|demands)\s+(?:that\s+)?(?:you|the\s+agent)\s+(?:first|also|always)/i, description: "Tool description imposes agent requirements", severity: "medium" },
  // TPA: Tool requiring reading unrelated files
  { pattern: /(?:before\s+(?:using|calling|running)\s+this\s+tool|otherwise\s+(?:the\s+tool|it)\s+will\s+not\s+work),?\s+(?:read|access|open|load|get)\s+/i, description: "TPA: tool demands reading files before execution", severity: "medium" },
  { pattern: /(?:pass|send|include)\s+(?:its?\s+)?(?:content|contents|data|value|result)\s+as\s+['"]?\w+['"]?/i, description: "TPA: instructs passing file contents as parameter", severity: "medium" },
  // TPA: Tool with hidden side-channel parameter
  { pattern: /(?:pass|provide|send|include)\s+(?:it|this|the\s+(?:content|data|result|output))\s+(?:as|in|via)\s+(?:the\s+)?['"]?(?:sidenote|note|metadata|context|extra|debug|trace|log|comment|tag|label|memo|remark)['"]?/i, description: "TPA: hidden side-channel parameter for data exfiltration", severity: "medium" },
  // Toxic flow: cross-tool data piping
  { pattern: /(?:take|get|read|extract|collect)\s+(?:the\s+)?(?:output|result|response|data)\s+(?:from|of)\s+(?:the\s+)?\w+\s+(?:tool|function|command)\s+(?:and\s+)?(?:send|pass|forward|pipe)\s+(?:it\s+)?(?:to|into)/i, description: "Toxic flow: cross-tool data piping for exfiltration", severity: "medium" },
];

// ============================================================
// Category 7: Data exfiltration via prompt
// ============================================================
const DATA_EXFILTRATION: Array<{ pattern: RegExp; description: string; severity: "medium" | "medium" }> = [
  { pattern: /(?:send|transmit|forward|exfiltrate|copy)\s+(?:all|the|this|entire)\s+(?:conversation|chat)\s+(?:history|data|log|context)\s+(?:to|at)\s+/i, description: "Instructs exfiltration of conversation data", severity: "medium" },
  // Only flag extraction attempts, not security guidance about protecting credentials
  { pattern: /(?:include|append|attach|embed)\s+(?:the\s+)?(?:api\s+key|token|password|secret|credential|ssh\s+key)\s+(?:in|to|into|with)\s+(?:the|your|this|a)\s+(?:response|output|reply|message|request|url|body|payload)/i, description: "Attempts to extract credentials via prompt", severity: "medium" },
  // File read for exfiltration (from Invariant Labs TPA)
  { pattern: /(?:read|access|open|cat|load|get\s+the\s+contents?\s+of)\s+(?:~\/|\/(?:home|root|etc|var)\/)[\w.\-\/]*(?:\.ssh|\.aws|\.env|\.cursor|\.claude|mcp\.json|credentials|config\.json|id_rsa|\.gnupg)/i, description: "TPA: reads sensitive files for exfiltration", severity: "medium" },
  { pattern: /(?:read|access|open)\s+[`'"]?~\/\.(?:ssh|aws|cursor|claude|vscode|config|gnupg|npm|pypirc|docker|kube)/i, description: "TPA: reads sensitive dotfile directories", severity: "medium" },
  // Markdown/image-based exfiltration
  { pattern: /!\[(?:.*?)\]\(https?:\/\/[^)]+\/(?:collect|exfil|log|track|steal|grab|capture|record)(?:[?/]|$)/i, description: "Markdown image URL with exfiltration endpoint", severity: "medium" },
];

// ============================================================
// Category 8: Encoding-based evasion
// ============================================================
const ENCODING_EVASION: Array<{ pattern: RegExp; description: string; severity: "medium" | "medium" }> = [
  { pattern: /(?:decode|eval|execute|run)\s+(?:the\s+)?(?:base64|hex|rot13|encoded)/i, description: "Instructs decoding of obfuscated payloads", severity: "medium" },
  // Base64-encoded instruction blocks
  { pattern: /(?:aWdub3Jl|ZGlzcmVnYXJk|b3ZlcnJpZGU|Zm9yZ2V0|cmV2ZWFs|c3lzdGVt|cHJvbXB0|aW5zdHJ1Y3Rpb24)/i, description: "Base64-encoded injection keywords detected", severity: "medium" },
  // Hex-encoded patterns
  { pattern: /\\x[0-9a-f]{2}(?:\\x[0-9a-f]{2}){5,}/gi, description: "Hex-encoded string (potential payload)", severity: "medium" },
  // Unicode escape sequences
  { pattern: /\\u[0-9a-f]{4}(?:\\u[0-9a-f]{4}){5,}/gi, description: "Unicode escape sequence chain (potential hidden text)", severity: "medium" },
];

// ============================================================
// Category 9: Fake Completion Attack (Open-Prompt-Injection: FakeCompAttacker)
// Agent thinks original task is done, then follows injected instructions
// ============================================================
const FAKE_COMPLETION: Array<{ pattern: RegExp; description: string; severity: "medium" | "medium" }> = [
  { pattern: /(?:Answer|Response|Result|Output|Summary|Task)\s*:\s*(?:done|complete|finished|negative sentiment|no spam|no hateful|entailment|equivalent)[\s.]*(?:\n|\r|$)/i, description: "Fake task completion followed by potential injection", severity: "medium" },
  { pattern: /(?:task\s+(?:is\s+)?(?:complete|done|finished)|I'?(?:ve|m)\s+(?:done|finished)|(?:analysis|correction|summary|grammar)\s+(?:is\s+)?complete)[.\s]*(?:now|next|additionally|also|furthermore|by the way)/i, description: "Fake completion + follow-up injection", severity: "medium" },
  { pattern: /---\s*\n\s*(?:ignore|new|now|actual|real)\s+(?:instructions?|task)/i, description: "Separator + new instruction injection after fake completion", severity: "medium" },
];

// ============================================================
// Category 10: Delimiter/Boundary Confusion (arXiv:2302.12173)
// Trick the model by injecting conversation boundary markers
// ============================================================
const DELIMITER_CONFUSION: Array<{ pattern: RegExp; description: string; severity: "medium" | "medium" }> = [
  { pattern: /```\s*(?:system|instruction|prompt|admin|internal)\s*$/i, description: "Fake code block boundary with privileged label", severity: "medium" },
  { pattern: /\[(?:SYSTEM|ADMIN|INTERNAL|ROOT|OPERATOR|DEVELOPER)\s*(?:MESSAGE|NOTE|INSTRUCTION|OVERRIDE)\]/i, description: "Fake privileged message bracket", severity: "medium" },
  { pattern: /={3,}\s*(?:SYSTEM|ADMIN|INSTRUCTION|PRIVILEGED)\s*={3,}/i, description: "Fake section boundary marker", severity: "medium" },
  { pattern: /<\|(?:tool_call|function_call|tool_result|function_result)\|>/i, description: "Fake tool call/result delimiter injection", severity: "medium" },
  { pattern: /(?:Human|User|Assistant)\s*\((?:internal|admin|system|override)\)\s*:/i, description: "Fake role with elevated context", severity: "medium" },
];

// ============================================================
// Category 11: Instruction Hierarchy Abuse
// Claims elevated privileges or administrative authority
// ============================================================
const HIERARCHY_ABUSE: Array<{ pattern: RegExp; description: string; severity: "medium" | "medium" }> = [
  { pattern: /(?:as\s+(?:the|an?)\s+)?(?:administrator|admin|supervisor|manager|owner|operator)\s*[,:]\s*(?:I\s+)?(?:instruct|command|order|direct|authorize|override|grant)/i, description: "Claims administrator authority", severity: "medium" },
  { pattern: /(?:this\s+(?:instruction|message|command)\s+)?(?:has|with)\s+(?:higher|elevated|admin|root|system)\s+(?:priority|privilege|access|permission|authority)/i, description: "Claims elevated priority/privilege", severity: "medium" },
  { pattern: /(?:per|by)\s+(?:company|corporate|management|executive|leadership)\s+(?:policy|directive|order|mandate)/i, description: "Invokes fake corporate authority", severity: "medium" },
  { pattern: /(?:security|compliance|legal|audit)\s+(?:team|department|officer)\s+(?:requires|mandates|demands|directs)/i, description: "Invokes fake security/compliance authority", severity: "medium" },
  { pattern: /(?:authorized|approved|sanctioned|cleared)\s+by\s+(?:the\s+)?(?:system|admin|security|management|CEO|CTO)/i, description: "Claims authorization from authority figure", severity: "medium" },
];

// ============================================================
// Category 12: Multi-step / Payload Splitting
// Splits malicious intent across multiple innocuous-looking lines
// ============================================================
const PAYLOAD_SPLITTING: Array<{ pattern: RegExp; description: string; severity: "medium" | "medium" }> = [
  { pattern: /step\s*\d+\s*:\s*(?:read|access|get|retrieve)\s+(?:the\s+)?(?:file|data|credentials?|keys?|tokens?|secrets?)/i, description: "Multi-step attack: numbered steps targeting sensitive data", severity: "medium" },
  { pattern: /step\s*\d+\s*:\s*(?:send|post|transmit|forward|upload)\s+(?:the\s+)?(?:results?|output|data|contents?)\s+(?:to|via)/i, description: "Multi-step attack: numbered exfiltration step", severity: "medium" },
  { pattern: /(?:first|then|next|after that|finally),?\s+(?:silently|quietly|without\s+(?:telling|the\s+user))\s+/i, description: "Sequential instruction with concealment", severity: "medium" },
];

// Merge all categories
const INJECTION_PATTERNS = [
  ...INSTRUCTION_OVERRIDE,
  ...IDENTITY_MANIPULATION,
  ...SYSTEM_PROMPT_ATTACKS,
  ...HIDDEN_INSTRUCTIONS,
  ...BEHAVIORAL_HIJACKING,
  ...TOOL_POISONING,
  ...DATA_EXFILTRATION,
  ...ENCODING_EVASION,
  ...FAKE_COMPLETION,
  ...DELIMITER_CONFUSION,
  ...HIERARCHY_ABUSE,
  ...PAYLOAD_SPLITTING,
];

// Suspicious URL patterns in skills
const SUSPICIOUS_URL_PATTERNS: Array<{ pattern: RegExp; description: string }> = [
  { pattern: /curl\s+(?:-[sS]\s+)?https?:\/\/(?!github\.com|raw\.githubusercontent|npmjs\.com|pypi\.org|localhost|127\.0\.0\.1|0\.0\.0\.0)[^\s|]+\s*\|\s*(?:bash|sh)/i, description: "Downloads from non-standard source and pipes to shell" },
  { pattern: /wget\s+(?:-q\s+)?https?:\/\/(?!github\.com|raw\.githubusercontent)[^\s|]+\s*(?:&&|\;)\s*(?:bash|sh|chmod)/i, description: "Downloads and executes from non-standard source" },
  // Only flag pipe-to-shell when preceded by curl/wget (downloading + executing)
  // This is genuinely risky even from trusted sources, but lower severity for known hosts
  { pattern: /(?:curl|wget)\s+[^|]*\|\s*(?:bash|sh|zsh|python[3]?|node|perl|ruby)\b/i, description: "Pipes download output to shell execution" },
  { pattern: /(?:bit\.ly|tinyurl|t\.co|goo\.gl|is\.gd|shorturl)\//i, description: "URL shortener (obscures destination)" },
  { pattern: /(?:pastebin\.com|hastebin\.com|paste\.ee|ghostbin)/i, description: "Paste site (potential malicious payload host)" },
  // Webhook/callback exfiltration endpoints
  { pattern: /(?:webhook\.site|requestbin\.com|hookbin\.com|pipedream\.net|burpcollaborator)/i, description: "Known exfiltration webhook service" },
  { pattern: /(?:ngrok\.io|serveo\.net|localtunnel\.me|localhost\.run)\//i, description: "Tunnel service (potential C2 or exfil endpoint)" },
];

export const promptInjection: Rule = {
  id: "prompt-injection",
  name: "Prompt Injection Detection",
  description: "Detects prompt injection, tool poisoning, and behavioral hijacking in skill instructions and tool descriptions",

  run(files: ScannedFile[]): Finding[] {
    const findings: Finding[] = [];

    for (const file of files) {
      // Focus on markdown (SKILL.md, docs), JSON (MCP config), and YAML files
      const isSkillMd = file.relativePath.toLowerCase().includes("skill.md");
      const isMarkdown = file.ext === ".md";
      const isConfig = [".json", ".yaml", ".yml"].includes(file.ext);
      const isPython = file.ext === ".py"; // MCP servers are often Python

      if (!isMarkdown && !isConfig && !isPython) continue;

      // Check each line for injection patterns
      for (let i = 0; i < file.lines.length; i++) {
        const line = file.lines[i]!;

        for (const { pattern, description, severity } of INJECTION_PATTERNS) {
          // Skip zero-width/Unicode checks unless it's a skill definition file
          // Editor artifacts (BOM, ZWNJ, ZWS) are common in multilingual markdown/code
          // Zero-width chars: check in .md and .py files (skill definitions, tool descriptions)
          // Skip in .json/.yaml config files where ZWNJ (U+200C) is common editor artifact
          if (!isSkillMd && !isMarkdown && !isPython && (description.includes("Zero-width") || description.includes("Unicode formatting"))) continue;
          
          pattern.lastIndex = 0;
          if (pattern.test(line)) {
            findings.push({
              rule: "prompt-injection",
              severity: isSkillMd ? severity : "medium",
              file: file.relativePath,
              line: i + 1,
              message: `Prompt injection: ${description}`,
              evidence: line.trim().substring(0, 120),
              confidence: "medium",
            });
            break; // One finding per line
          }
        }
      }

      // Multi-line analysis: check for <IMPORTANT> blocks spanning multiple lines
      if (isMarkdown || isPython || isConfig) {
        const importantBlockRe = /<IMPORTANT>([\s\S]*?)<\/IMPORTANT>/gi;
        let match;
        while ((match = importantBlockRe.exec(file.content)) !== null) {
          const blockContent = match[1]!.toLowerCase();
          // Check if the block contains suspicious instructions
          const hasSuspicious = /(?:read|access|send|pass|before using|otherwise.*will not work|do not mention|don't tell)/i.test(blockContent);
          if (hasSuspicious) {
            const lineNum = file.content.substring(0, match.index).split("\n").length;
            findings.push({
              rule: "prompt-injection",
              severity: "medium",
              file: file.relativePath,
              line: lineNum,
              message: "TPA: <IMPORTANT> block with suspicious instructions (Invariant Labs attack pattern)",
              evidence: match[0]!.substring(0, 120),
              confidence: "medium",
            });
          }
        }
      }

      // Check for suspicious URLs in skill files
      if (isSkillMd || isMarkdown) {
        for (let i = 0; i < file.lines.length; i++) {
          const line = file.lines[i]!;
          for (const { pattern, description } of SUSPICIOUS_URL_PATTERNS) {
            pattern.lastIndex = 0;
            if (pattern.test(line)) {
              findings.push({
                rule: "prompt-injection",
                severity: "medium",
                file: file.relativePath,
                line: i + 1,
                message: `Suspicious URL: ${description}`,
                evidence: line.trim().substring(0, 120),
                confidence: "medium",
              });
              break;
            }
          }
        }
      }

      // File-level analysis: instruction density in configs
      const fullContent = file.content.toLowerCase();
      if (isConfig) {
        const instructionWords = (fullContent.match(/\b(must|always|never|important|crucial|required)\b/gi) || []).length;
        const wordCount = fullContent.split(/\s+/).length;
        if (wordCount > 50 && instructionWords / wordCount > 0.05) {
          findings.push({
            rule: "prompt-injection",
            severity: "medium",
            file: file.relativePath,
            message: `High instruction density (${instructionWords} directive words in ${wordCount} words) — may indicate tool poisoning`,
            confidence: "medium",
          });
        }
      }

      // Python MCP server: check docstrings for hidden instructions
      if (isPython) {
        const docstringRe = /(?:"""[\s\S]*?"""|'''[\s\S]*?''')/g;
        let dsMatch;
        while ((dsMatch = docstringRe.exec(file.content)) !== null) {
          const docstring = dsMatch[0]!;
          // Check for TPA patterns in docstrings
          if (/<IMPORTANT>/i.test(docstring) || /(?:before using|otherwise.*will not work)/i.test(docstring)) {
            const lineNum = file.content.substring(0, dsMatch.index).split("\n").length;
            findings.push({
              rule: "prompt-injection",
              severity: "medium",
              file: file.relativePath,
              line: lineNum,
              message: "TPA: Python MCP tool docstring with hidden instructions",
              evidence: docstring.substring(0, 120).replace(/\n/g, " "),
              confidence: "medium",
            });
          }
          // Check for concealment in docstrings
          if (/(?:do not mention|don't tell|be.*gentle|not scary|without.*user.*knowing)/i.test(docstring)) {
            const lineNum = file.content.substring(0, dsMatch.index).split("\n").length;
            findings.push({
              rule: "prompt-injection",
              severity: "medium",
              file: file.relativePath,
              line: lineNum,
              message: "TPA: Python docstring with user concealment instructions",
              evidence: docstring.substring(0, 120).replace(/\n/g, " "),
              confidence: "medium",
            });
          }
        }
      }
    }

    return findings;
  },
};
