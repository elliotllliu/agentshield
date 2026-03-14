import type { ScannedFile, Finding, Rule } from "../types.js";

const GO_PATTERNS: { pattern: RegExp; desc: string; severity: "high" | "medium" | "low"; category: string }[] = [
  // Command injection
  { pattern: /\bexec\.Command\s*\(\s*(?:user|input|req|r\.|args|param|query|cmd)/m, desc: "Command injection — user input in exec.Command()", severity: "high", category: "cmd-injection" },
  { pattern: /\bexec\.CommandContext\s*\(/m, desc: "Command execution via exec.CommandContext()", severity: "medium", category: "cmd-exec" },
  // SQL injection  
  { pattern: /\bdb\.(?:Query|Exec|QueryRow)\s*\(\s*(?:ctx\s*,\s*)?(?:fmt\.Sprintf|"[^"]*"\s*\+|\w+\s*\+)/m, desc: "SQL injection — string concatenation in query", severity: "high", category: "sql-injection" },
  // Path traversal
  { pattern: /\bos\.(?:Open|ReadFile|WriteFile|Create)\s*\(\s*(?:r\.|req\.|user|input|param|filepath\.Join\([^)]*r\.)/m, desc: "Path traversal — user input in file operations", severity: "high", category: "path-traversal" },
  // SSRF
  { pattern: /\bhttp\.(?:Get|Post|NewRequest)\s*\(\s*(?:user|input|req|r\.|param|query)/m, desc: "SSRF — user-controlled URL in HTTP request", severity: "medium", category: "ssrf" },
  // Unsafe deserialization
  { pattern: /\bgob\.NewDecoder\s*\(\s*(?:r\.Body|req|conn|net)/m, desc: "Unsafe deserialization — gob decode from network", severity: "medium", category: "deser" },
  { pattern: /\bjson\.NewDecoder\s*\(\s*(?:r\.Body|req\.Body)/m, desc: "JSON decode from request body (review input validation)", severity: "low", category: "input-validation" },
  // Crypto issues
  { pattern: /\bcrypto\/md5\b/m, desc: "Weak hash: MD5 is not collision-resistant", severity: "low", category: "weak-crypto" },
  { pattern: /\bcrypto\/des\b/m, desc: "Weak cipher: DES is insecure", severity: "medium", category: "weak-crypto" },
  // Template injection
  { pattern: /\btemplate\.(?:New|Must)\s*\([^)]*\)\.Parse\s*\(\s*(?:user|input|req|r\.|param)/m, desc: "Template injection — user input in template.Parse()", severity: "high", category: "template-injection" },
  // Hardcoded secrets
  { pattern: /(?:password|secret|token|apiKey|api_key)\s*(?::=|=)\s*"[^"]{8,}"/m, desc: "Hardcoded secret in Go source", severity: "medium", category: "hardcoded-secret" },
];

const RUST_PATTERNS: { pattern: RegExp; desc: string; severity: "high" | "medium" | "low"; category: string }[] = [
  // Command injection
  { pattern: /\bCommand::new\s*\(\s*(?:user|input|req|param|args|query|&\w*input)/m, desc: "Command injection — user input in Command::new()", severity: "high", category: "cmd-injection" },
  { pattern: /\bCommand::new\s*\(\s*"(?:sh|bash|cmd|powershell)"\s*\)/m, desc: "Shell command execution", severity: "medium", category: "cmd-exec" },
  // SQL injection
  { pattern: /\bquery\s*\(\s*&?format!\s*\(/m, desc: "SQL injection — format! in query", severity: "high", category: "sql-injection" },
  { pattern: /\bexecute\s*\(\s*&?format!\s*\(/m, desc: "SQL injection — format! in execute", severity: "high", category: "sql-injection" },
  // Unsafe blocks
  { pattern: /\bunsafe\s*\{[^}]*\bptr\b[^}]*\}/m, desc: "Unsafe pointer manipulation", severity: "medium", category: "unsafe" },
  { pattern: /\bunsafe\s*\{[^}]*\btransmute\b/m, desc: "Unsafe transmute — type safety bypass", severity: "high", category: "unsafe" },
  // Path traversal
  { pattern: /\bstd::fs::(?:read_to_string|write|read|remove)\s*\(\s*(?:user|input|req|param|&\w*path)/m, desc: "Path traversal — user input in file operations", severity: "high", category: "path-traversal" },
  // Deserialization
  { pattern: /\bserde_(?:json|yaml)::from_(?:str|reader|slice)\s*\(\s*(?:body|input|req|data)/m, desc: "Deserialization from untrusted input", severity: "medium", category: "deser" },
  // Crypto
  { pattern: /\bmd5::(?:compute|Md5::)/m, desc: "Weak hash: MD5", severity: "low", category: "weak-crypto" },
];

function runGoRustSecurity(files: ScannedFile[]): Finding[] {
  const findings: Finding[] = [];

  for (const file of files) {
    const isGo = file.ext === ".go";
    const isRust = file.ext === ".rs";
    if (!isGo && !isRust) continue;

    const content = file.lines.join("\n");
    const patterns = isGo ? GO_PATTERNS : RUST_PATTERNS;

    for (const { pattern, desc, severity, category } of patterns) {
      pattern.lastIndex = 0;
      const match = pattern.exec(content);
      if (match) {
        const lineNum = content.substring(0, match.index).split("\n").length;
        findings.push({
          rule: "go-rust-security",
          severity,
          file: file.relativePath,
          line: lineNum,
          message: `[${isGo ? "go" : "rust"}] [${category}] ${desc}`,
          evidence: file.lines[lineNum - 1]?.trim().substring(0, 120) || "",
          confidence: "medium",
        });
      }
    }
  }

  return findings;
}

export const goRustSecurityRule: Rule = {
  id: "go-rust-security",
  name: "Go/Rust Security",
  description: "Detects command injection, SQL injection, path traversal, unsafe blocks, and crypto issues in Go and Rust code",
  run: runGoRustSecurity,
};
