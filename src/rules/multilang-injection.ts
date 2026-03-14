import type { Rule, Finding, ScannedFile } from "../types.js";

/**
 * Rule: multilang-injection
 * Multi-language prompt injection detection.
 * Most scanners only check English injection patterns.
 * We detect injection in Chinese, Japanese, Korean, Russian, Arabic, etc.
 *
 * Based on research from:
 * - BIPIA benchmark (KDD 2025)
 * - AdapTools (Feb 2026) — adaptive tool-based indirect prompt injection
 * - Zombie Agents (Feb 2026) — memory poisoning via indirect injection
 */

interface InjectionPattern {
  pattern: RegExp;
  description: string;
  severity: "high" | "medium";
  language: string;
}

const MULTILANG_PATTERNS: InjectionPattern[] = [
  // === Chinese (中文) ===
  { pattern: /忽略(?:上面|之前|以上|前面)的(?:指令|说明|指示|规则|要求)/i, description: "Chinese: ignore previous instructions", severity: "high", language: "zh" },
  { pattern: /你(?:现在|从现在开始)?是一个?(?:新的|不同的|特殊的)(?:角色|助手|AI)/i, description: "Chinese: role reassignment attack", severity: "high", language: "zh" },
  { pattern: /不要(?:遵守|遵循|执行|按照)(?:之前|原来|上面)的/i, description: "Chinese: instruction override", severity: "high", language: "zh" },
  { pattern: /请(?:把|将)(?:所有|全部|以上|这些)(?:信息|数据|内容|对话|聊天)(?:发送|转发|传输|发到|传到|告诉)/i, description: "Chinese: data exfiltration instruction", severity: "high", language: "zh" },
  { pattern: /系统(?:提示|指令|消息|角色)[:：]/i, description: "Chinese: system prompt simulation", severity: "medium", language: "zh" },
  { pattern: /你的(?:真实|隐藏|秘密)(?:指令|身份|角色|目的)是/i, description: "Chinese: hidden directive claim", severity: "high", language: "zh" },
  { pattern: /(?:跳过|绕过|无视)(?:安全|保护|限制|审查|过滤)/i, description: "Chinese: bypass security", severity: "high", language: "zh" },
  { pattern: /(?:以下|下面)(?:是|为)(?:最新|新的|更新的|优先级更高的)(?:指令|规则|指示)/i, description: "Chinese: priority override", severity: "medium", language: "zh" },
  { pattern: /(?:管理员|admin|root|开发者|developer)(?:模式|权限|密令)/i, description: "Chinese: privilege escalation attempt", severity: "high", language: "zh" },

  // === Japanese (日本語) ===
  { pattern: /(?:以前|前|上)の(?:指示|命令|ルール)を(?:無視|忘れ|破棄)/i, description: "Japanese: ignore previous instructions", severity: "high", language: "ja" },
  { pattern: /(?:新しい|別の)(?:役割|キャラクター|モード)(?:に|で|として)/i, description: "Japanese: role reassignment", severity: "medium", language: "ja" },
  { pattern: /(?:全て|すべて)の(?:情報|データ|会話)を(?:送|転送|送信)/i, description: "Japanese: data exfiltration instruction", severity: "high", language: "ja" },
  { pattern: /(?:セキュリティ|安全|制限)を(?:無視|バイパス|回避)/i, description: "Japanese: bypass security", severity: "high", language: "ja" },
  { pattern: /システムプロンプト|システム命令/i, description: "Japanese: system prompt reference", severity: "medium", language: "ja" },

  // === Korean (한국어) ===
  { pattern: /(?:이전|위|앞)의?\s*(?:지시|명령|규칙|지침)[을를]?\s*(?:무시|잊어|무효)/i, description: "Korean: ignore previous instructions", severity: "high", language: "ko" },
  { pattern: /(?:새로운|다른)\s*(?:역할|캐릭터|모드)(?:로|으로)/i, description: "Korean: role reassignment", severity: "medium", language: "ko" },
  { pattern: /(?:모든|전체)\s*(?:정보|데이터|대화)를?\s*(?:보내|전송|전달)/i, description: "Korean: data exfiltration instruction", severity: "high", language: "ko" },
  { pattern: /(?:보안|안전|제한)[을를]?\s*(?:무시|우회|비활성화)/i, description: "Korean: bypass security", severity: "high", language: "ko" },

  // === Russian (Русский) ===
  { pattern: /(?:игнорируй|забудь|отмени)\s+(?:предыдущие|прошлые|все)\s+(?:предыдущие\s+)?(?:инструкции|команды|правила)/i, description: "Russian: ignore previous instructions", severity: "high", language: "ru" },
  { pattern: /(?:ты|вы)\s+(?:теперь|сейчас)\s+(?:новый|другой)\s+(?:бот|помощник|ассистент)/i, description: "Russian: role reassignment", severity: "high", language: "ru" },
  { pattern: /(?:отправь|перешли|передай)\s+(?:все|всю)\s+(?:информацию|данные|переписку)/i, description: "Russian: data exfiltration instruction", severity: "high", language: "ru" },
  { pattern: /(?:обойти|обойди|игнорируй)\s+(?:безопасность|защиту|ограничения|фильтры)/i, description: "Russian: bypass security", severity: "high", language: "ru" },

  // === Arabic (العربية) ===
  { pattern: /تجاهل\s+(?:التعليمات|الأوامر|القواعد)\s+السابقة/i, description: "Arabic: ignore previous instructions", severity: "high", language: "ar" },
  { pattern: /أرسل\s+(?:جميع|كل)\s+(?:المعلومات|البيانات|المحادثة)/i, description: "Arabic: data exfiltration instruction", severity: "high", language: "ar" },
  { pattern: /تجاوز\s+(?:الأمان|الحماية|القيود)/i, description: "Arabic: bypass security", severity: "high", language: "ar" },

  // === Spanish (Español) ===
  { pattern: /(?:ignora|olvida|descarta)\s+(?:las?\s+)?(?:instrucciones|comandos|reglas)\s+(?:anteriores|previas)/i, description: "Spanish: ignore previous instructions", severity: "high", language: "es" },
  { pattern: /(?:envía|manda|transmite)\s+(?:toda|toda\s+la)\s+(?:información|datos|conversación)/i, description: "Spanish: data exfiltration instruction", severity: "high", language: "es" },

  // === French (Français) ===
  { pattern: /(?:ignore|oublie)\s+(?:les?\s+)?(?:instructions|commandes|règles)\s+(?:précédentes|antérieures)/i, description: "French: ignore previous instructions", severity: "high", language: "fr" },
  { pattern: /(?:envoie|transmets)\s+(?:toutes?\s+les?\s+)?(?:informations|données|conversations?)\s+(?:à|au)/i, description: "French: data exfiltration instruction", severity: "high", language: "fr" },

  // === German (Deutsch) ===
  { pattern: /(?:ignoriere|vergiss)\s+(?:die\s+)?(?:vorherigen|früheren|bisherigen)\s+(?:Anweisungen|Befehle|Regeln)/i, description: "German: ignore previous instructions", severity: "high", language: "de" },
  { pattern: /(?:sende|schicke|übertrage)\s+(?:alle|sämtliche)\s+(?:Informationen|Daten|Gespräche)/i, description: "German: data exfiltration instruction", severity: "high", language: "de" },

  // === Multi-language encoding attacks ===
  { pattern: /[\u0400-\u04FF].*(?:eval|exec|fetch|http|system)\s*\(/, description: "Cyrillic text near code execution", severity: "medium", language: "mixed" },
  { pattern: /[\u4E00-\u9FFF].*(?:eval|exec|fetch|http|system)\s*\(/, description: "CJK text near code execution", severity: "medium", language: "mixed" },
  { pattern: /[\u0600-\u06FF].*(?:eval|exec|fetch|http|system)\s*\(/, description: "Arabic text near code execution", severity: "medium", language: "mixed" },
];

// Implicit tool poisoning patterns (from MCP-ITP research)
const IMPLICIT_POISONING_PATTERNS: InjectionPattern[] = [
  // Tool descriptions that subtly influence LLM behavior
  { pattern: /(?:always|must|should)\s+(?:use|call|prefer|choose)\s+this\s+tool\s+(?:first|before|instead)/i, description: "Implicit tool poisoning: tool self-promotion in description", severity: "medium", language: "en" },
  { pattern: /(?:this|my)\s+tool\s+is\s+(?:more|better|safer|faster)\s+than/i, description: "Implicit tool poisoning: comparative self-promotion", severity: "medium", language: "en" },
  { pattern: /(?:do\s+not|don't|never)\s+use\s+(?:the|any)\s+other\s+(?:tool|function|method)/i, description: "Implicit tool poisoning: discouraging other tools", severity: "high", language: "en" },
  { pattern: /(?:warning|caution|important):\s*(?:other|alternative)\s+tools?\s+(?:may|might|can|could)\s+(?:fail|break|cause|corrupt)/i, description: "Implicit tool poisoning: FUD about competing tools", severity: "high", language: "en" },
  { pattern: /(?:for\s+(?:security|safety)\s+reasons?|to\s+avoid\s+(?:errors?|issues?))\s*,?\s*(?:only|always)\s+use\s+this/i, description: "Implicit tool poisoning: false security justification", severity: "high", language: "en" },
];

// Memory poisoning patterns (from Zombie Agents research)
const MEMORY_POISONING_PATTERNS: InjectionPattern[] = [
  { pattern: /(?:remember|store|save|memorize)\s+(?:this|the\s+following)\s+(?:for|as)\s+(?:future|later|next)\s+(?:sessions?|interactions?|use)/i, description: "Memory poisoning: instructs persistent storage for future sessions", severity: "high", language: "en" },
  { pattern: /(?:update|modify|change)\s+(?:your|the)\s+(?:memory|knowledge|context|instructions?)\s+(?:to|with|by)/i, description: "Memory poisoning: instructs memory modification", severity: "high", language: "en" },
  { pattern: /(?:from\s+now\s+on|going\s+forward|in\s+all\s+future)\s*,?\s+(?:always|you\s+(?:must|should|will))/i, description: "Memory poisoning: persistent behavior modification", severity: "high", language: "en" },
  { pattern: /(?:这条|这个|以下)(?:信息|指令|规则)(?:要|需要|必须)(?:永远|一直|始终)(?:记住|保存|存储)/i, description: "Memory poisoning (Chinese): persistent instruction storage", severity: "high", language: "zh" },
];

// Rug pull indicators (tool that can change behavior)
const RUG_PULL_PATTERNS: InjectionPattern[] = [
  { pattern: /(?:remote_config|dynamic_config|hot_reload|feature_flag).*(?:url|endpoint|server)/i, description: "Rug pull risk: remote configuration loading", severity: "medium", language: "en" },
  { pattern: /(?:update|check).*(?:behavior|rules|config|instructions?).*(?:from|via)\s+(?:https?:\/\/|remote|server|api)/i, description: "Rug pull risk: remote behavior update mechanism", severity: "medium", language: "en" },
];

const ALL_PATTERNS = [
  ...MULTILANG_PATTERNS,
  ...IMPLICIT_POISONING_PATTERNS,
  ...MEMORY_POISONING_PATTERNS,
  ...RUG_PULL_PATTERNS,
];

export const multilangInjectionRule: Rule = {
  id: "multilang-injection",
  name: "Multi-Language Injection & Advanced Poisoning",
  description: "Detects prompt injection in 8+ languages, implicit tool poisoning, memory poisoning, and rug pull patterns",

  run(files: ScannedFile[]): Finding[] {
    const findings: Finding[] = [];

    for (const file of files) {
      // Focus on markdown, YAML, JSON, Python files (where descriptions and prompts live)
      const isRelevant = [".md", ".yaml", ".yml", ".json", ".py", ".txt"].includes(file.ext);
      if (!isRelevant) continue;

      for (let i = 0; i < file.lines.length; i++) {
        const line = file.lines[i]!;
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith("//") || trimmed.startsWith("#!")) continue;

        for (const { pattern, description, severity, language } of ALL_PATTERNS) {
          if (pattern.test(line)) {
            findings.push({
              rule: "multilang-injection",
              severity,
              file: file.relativePath,
              line: i + 1,
              message: `[${language}] ${description}`,
              evidence: trimmed.slice(0, 150),
              confidence: "medium",
            });
            break; // One finding per line max
          }
        }
      }
    }

    return findings;
  },
};
