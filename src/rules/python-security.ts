import type { Rule, Finding, ScannedFile } from "../types.js";

/**
 * Rule: python-security
 * Detects Python-specific security anti-patterns:
 * - Dangerous builtins (eval, exec, compile)
 * - Unsafe deserialization (pickle, marshal, yaml.load)
 * - Command injection (subprocess with shell=True, os.system, os.popen)
 * - Path traversal (open with user input)
 * - SQL injection (string formatting in queries)
 * - Insecure crypto/network (ssl unverified, hardcoded secrets)
 * - Dynamic imports and code loading
 */

const PYTHON_PATTERNS: Array<{ pattern: RegExp; desc: string; severity: "high" | "medium" | "low"; category: string }> = [
  // === HIGH RISK: Code execution ===
  { pattern: /\beval\s*\(\s*(?!["'](?:True|False|None|[0-9]))/m, desc: "eval() with non-literal input", severity: "high", category: "code-exec" },
  { pattern: /\bexec\s*\(\s*(?!["'](?:pass|$))/m, desc: "exec() with dynamic input", severity: "high", category: "code-exec" },
  { pattern: /\bcompile\s*\(.*\bexec\b/m, desc: "compile() + exec — dynamic code execution", severity: "high", category: "code-exec" },
  { pattern: /\b__import__\s*\(/m, desc: "__import__() — dynamic module loading", severity: "high", category: "code-exec" },
  { pattern: /\bgetattr\s*\(.*,\s*(?:request|input|params|args|kwargs)/m, desc: "getattr() with user-controlled attribute", severity: "high", category: "code-exec" },
  
  // === HIGH RISK: Command injection ===
  { pattern: /\bos\.system\s*\(/m, desc: "os.system() — vulnerable to command injection", severity: "high", category: "cmd-injection" },
  { pattern: /\bos\.popen\s*\(/m, desc: "os.popen() — vulnerable to command injection", severity: "high", category: "cmd-injection" },
  { pattern: /subprocess\.(?:call|run|Popen|check_output|check_call)\s*\([^)]*shell\s*=\s*True/m, desc: "subprocess with shell=True", severity: "high", category: "cmd-injection" },
  { pattern: /subprocess\.(?:call|run|Popen|check_output|check_call)\s*\(\s*f["']/m, desc: "subprocess with f-string — command injection risk", severity: "high", category: "cmd-injection" },
  { pattern: /subprocess\.(?:call|run|Popen)\s*\(\s*(?:cmd|command|user_input|args)/m, desc: "subprocess with variable input", severity: "medium", category: "cmd-injection" },
  
  // === HIGH RISK: Unsafe deserialization ===
  { pattern: /pickle\.loads?\s*\(/m, desc: "pickle.load/loads — arbitrary code execution via deserialization", severity: "high", category: "deserialization" },
  { pattern: /\bcPickle\b/m, desc: "cPickle — unsafe deserialization", severity: "high", category: "deserialization" },
  { pattern: /marshal\.loads?\s*\(/m, desc: "marshal.load — unsafe deserialization", severity: "high", category: "deserialization" },
  { pattern: /shelve\.open\s*\(/m, desc: "shelve.open — uses pickle internally, unsafe with untrusted data", severity: "medium", category: "deserialization" },
  { pattern: /yaml\.load\s*\([^)]*(?!Loader)/m, desc: "yaml.load without safe Loader — code execution risk", severity: "high", category: "deserialization" },
  { pattern: /yaml\.unsafe_load/m, desc: "yaml.unsafe_load — arbitrary code execution", severity: "high", category: "deserialization" },
  { pattern: /jsonpickle\.decode/m, desc: "jsonpickle.decode — unsafe deserialization", severity: "high", category: "deserialization" },
  
  // === MEDIUM RISK: SQL injection ===
  { pattern: /(?:execute|cursor\.execute)\s*\(\s*f["']/m, desc: "SQL query with f-string — SQL injection risk", severity: "medium", category: "sql-injection" },
  { pattern: /(?:execute|cursor\.execute)\s*\(\s*["'].*%s.*["']\s*%/m, desc: "SQL query with % formatting — SQL injection risk", severity: "medium", category: "sql-injection" },
  { pattern: /(?:execute|cursor\.execute)\s*\(\s*.*\.format\s*\(/m, desc: "SQL query with .format() — SQL injection risk", severity: "medium", category: "sql-injection" },
  { pattern: /\braw\s*\(\s*f?["'].*(?:SELECT|INSERT|UPDATE|DELETE|DROP)/im, desc: "Django raw SQL with string interpolation", severity: "medium", category: "sql-injection" },
  
  // === MEDIUM RISK: Path traversal ===
  { pattern: /open\s*\(\s*(?:os\.path\.join\s*\()?.*(?:request\.|params\[|query\[|form\[|args\[)/m, desc: "open() with web request input — path traversal risk", severity: "medium", category: "path-traversal" },
  { pattern: /send_file\s*\(\s*(?!['"])/m, desc: "Flask send_file with variable — path traversal risk", severity: "medium", category: "path-traversal" },
  
  // === MEDIUM RISK: Insecure network ===
  { pattern: /verify\s*=\s*False/m, desc: "SSL verification disabled (verify=False)", severity: "medium", category: "insecure-network" },
  { pattern: /ssl\._create_unverified_context/m, desc: "Unverified SSL context", severity: "medium", category: "insecure-network" },
  { pattern: /CERT_NONE/m, desc: "SSL CERT_NONE — no certificate verification", severity: "medium", category: "insecure-network" },
  
  // === MEDIUM RISK: Insecure crypto ===
  { pattern: /\bmd5\s*\(|hashlib\.md5/m, desc: "MD5 hash — cryptographically weak", severity: "low", category: "weak-crypto" },
  { pattern: /\bsha1\s*\(|hashlib\.sha1/m, desc: "SHA1 hash — cryptographically weak", severity: "low", category: "weak-crypto" },
  { pattern: /\brandom\b(?!\.SystemRandom).*(?:password|secret|token|key|salt)/im, desc: "random module for security-sensitive value (use secrets module)", severity: "medium", category: "weak-crypto" },
  
  // === MEDIUM RISK: Dangerous patterns ===
  { pattern: /\bTemplate\s*\(\s*(?:user|input|request|data|query|param|args|body|payload|content|text|msg|message|template_str|user_input)/m, desc: "Server-side template injection (SSTI) — user input in Template()", severity: "high", category: "ssti" },
  { pattern: /\bTemplate\s*\(\s*["'].*['"]\s*\+\s*\w+/m, desc: "Server-side template injection (SSTI) — string concat in Template()", severity: "medium", category: "ssti" },
  { pattern: /\bMarkup\s*\(\s*f["']/m, desc: "Jinja2 Markup with f-string — XSS risk", severity: "medium", category: "xss" },
  { pattern: /\bHTMLParser\s*\(/m, desc: "HTMLParser — ensure proper sanitization", severity: "low", category: "xss" },
  
  // === LOW RISK: Debug/info ===
  { pattern: /\bDEBUG\s*=\s*True/m, desc: "DEBUG mode enabled — disable in production", severity: "low", category: "debug" },
  { pattern: /\bapp\.run\s*\(.*debug\s*=\s*True/m, desc: "Flask debug mode — disable in production", severity: "low", category: "debug" },
  { pattern: /\bprint\s*\(.*(?:password|secret_key|private_key|api_secret)\b/im, desc: "Printing sensitive data", severity: "low", category: "info-leak" },
];

export const pythonSecurityRule: Rule = {
  id: "python-security",
  name: "Python Security",
  description: "Detects Python-specific security anti-patterns (eval, pickle, subprocess, SQL injection, etc.)",
  run(files: ScannedFile[]): Finding[] {
    const findings: Finding[] = [];
    const pyFiles = files.filter(f => f.ext === ".py");
    
    for (const file of pyFiles) {
      for (const { pattern, desc, severity, category } of PYTHON_PATTERNS) {
        for (let i = 0; i < file.lines.length; i++) {
          const line = file.lines[i]!;
          
          // Skip comments
          if (line.trimStart().startsWith("#")) continue;
          // Skip docstrings (rough heuristic)
          if (line.trimStart().startsWith('"""') || line.trimStart().startsWith("'''")) continue;
          
          if (pattern.test(line)) {
            findings.push({
              rule: "python-security",
              severity,
              file: file.relativePath,
              line: i + 1,
              message: `[${category}] ${desc}`,
              evidence: line.trim().slice(0, 120),
              confidence: "medium",
            });
          }
        }
      }
    }
    
    return findings;
  },
};
