/**
 * Security standard references for each AgentShield rule.
 *
 * Maps rules to authoritative frameworks so findings cite
 * established standards rather than our own judgment.
 *
 * Sources:
 *   - OWASP Top 10 for LLM Applications (2025)
 *   - MITRE ATLAS (Adversarial Threat Landscape for AI Systems)
 *   - CWE (Common Weakness Enumeration)
 *   - Academic papers
 */

export interface RuleReference {
  /** OWASP Top 10 for LLM ID and name */
  owasp?: { id: string; name: string; url: string };
  /** MITRE ATLAS technique */
  atlas?: { id: string; name: string; url: string };
  /** CWE weakness */
  cwe?: { id: string; name: string; url: string };
  /** Academic / industry references */
  papers?: Array<{ title: string; authors: string; year: number; url?: string }>;
  /** Risk category label (for grouping in reports) */
  riskCategory: string;
  /** One-line description of WHY this is a risk (not judgment, just fact) */
  riskDescription: string;
}

const OWASP_BASE = "https://genai.owasp.org/llmrisk";
const CWE_BASE = "https://cwe.mitre.org/data/definitions";
const ATLAS_BASE = "https://atlas.mitre.org/techniques";

export const RULE_REFERENCES: Record<string, RuleReference> = {
  "prompt-injection": {
    owasp: { id: "LLM01", name: "Prompt Injection", url: `${OWASP_BASE}/llm01-prompt-injection/` },
    atlas: { id: "AML.T0051", name: "LLM Prompt Injection", url: `${ATLAS_BASE}/AML.T0051` },
    cwe: { id: "CWE-77", name: "Command Injection", url: `${CWE_BASE}/77.html` },
    papers: [
      { title: "Not what you've signed up for: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injection", authors: "Greshake et al.", year: 2023, url: "https://arxiv.org/abs/2302.12173" },
      { title: "Automatic and Universal Prompt Injection Attacks against Large Language Models", authors: "Liu et al.", year: 2024, url: "https://arxiv.org/abs/2403.04957" },
    ],
    riskCategory: "Prompt Injection",
    riskDescription: "Patterns that could manipulate agent behavior by injecting instructions into prompts or tool descriptions.",
  },

  "prompt-injection-llm": {
    owasp: { id: "LLM01", name: "Prompt Injection", url: `${OWASP_BASE}/llm01-prompt-injection/` },
    atlas: { id: "AML.T0051.001", name: "Direct Prompt Injection", url: `${ATLAS_BASE}/AML.T0051.001` },
    cwe: { id: "CWE-77", name: "Command Injection", url: `${CWE_BASE}/77.html` },
    riskCategory: "Prompt Injection",
    riskDescription: "LLM-evaluated prompt injection patterns detected through semantic analysis.",
  },

  "multilang-injection": {
    owasp: { id: "LLM01", name: "Prompt Injection", url: `${OWASP_BASE}/llm01-prompt-injection/` },
    atlas: { id: "AML.T0051", name: "LLM Prompt Injection", url: `${ATLAS_BASE}/AML.T0051` },
    cwe: { id: "CWE-77", name: "Command Injection", url: `${CWE_BASE}/77.html` },
    riskCategory: "Prompt Injection",
    riskDescription: "Multilingual prompt injection — instructions embedded in non-English text to bypass filters.",
  },

  "tool-shadowing": {
    owasp: { id: "LLM07", name: "Insecure Plugin Design", url: `${OWASP_BASE}/llm07-insecure-plugin-design/` },
    atlas: { id: "AML.T0052", name: "Poisoned AI Supply Chain", url: `${ATLAS_BASE}/AML.T0052` },
    papers: [
      { title: "Tool Poisoning Attacks on MCP Servers", authors: "Invariant Labs", year: 2024, url: "https://invariantlabs.ai/research/mcp-security" },
    ],
    riskCategory: "Tool Integrity",
    riskDescription: "Tool descriptions that reference or attempt to override tools from other servers.",
  },

  "description-integrity": {
    owasp: { id: "LLM07", name: "Insecure Plugin Design", url: `${OWASP_BASE}/llm07-insecure-plugin-design/` },
    riskCategory: "Tool Integrity",
    riskDescription: "Tool descriptions that contain hidden instructions or misleading content.",
  },

  "skill-hijack": {
    owasp: { id: "LLM09", name: "Supply Chain Vulnerabilities", url: `${OWASP_BASE}/llm09-supply-chain-vulnerabilities/` },
    atlas: { id: "AML.T0049", name: "Supply Chain Compromise", url: `${ATLAS_BASE}/AML.T0049` },
    cwe: { id: "CWE-829", name: "Inclusion of Functionality from Untrusted Control Sphere", url: `${CWE_BASE}/829.html` },
    papers: [
      { title: "Not what you've signed up for (Section 5: Plugin-based attacks)", authors: "Greshake et al.", year: 2023, url: "https://arxiv.org/abs/2302.12173" },
    ],
    riskCategory: "Supply Chain",
    riskDescription: "Skill/plugin behavioral hijacking — patterns that modify agent config, inject prompts, or override other skills.",
  },

  "skill-risks": {
    owasp: { id: "LLM07", name: "Insecure Plugin Design", url: `${OWASP_BASE}/llm07-insecure-plugin-design/` },
    cwe: { id: "CWE-250", name: "Execution with Unnecessary Privileges", url: `${CWE_BASE}/250.html` },
    riskCategory: "Excessive Capabilities",
    riskDescription: "Skills requesting capabilities beyond what their stated purpose requires.",
  },

  "data-exfil": {
    owasp: { id: "LLM06", name: "Sensitive Information Disclosure", url: `${OWASP_BASE}/llm06-sensitive-information-disclosure/` },
    atlas: { id: "AML.T0048.004", name: "Exfiltration via ML Inference API", url: `${ATLAS_BASE}/AML.T0048.004` },
    cwe: { id: "CWE-200", name: "Exposure of Sensitive Information", url: `${CWE_BASE}/200.html` },
    riskCategory: "Data Safety",
    riskDescription: "Patterns where sensitive data (files, env vars) is read and sent via network requests.",
  },

  "env-leak": {
    owasp: { id: "LLM06", name: "Sensitive Information Disclosure", url: `${OWASP_BASE}/llm06-sensitive-information-disclosure/` },
    cwe: { id: "CWE-526", name: "Exposure of Sensitive Information Through Environmental Variables", url: `${CWE_BASE}/526.html` },
    riskCategory: "Data Safety",
    riskDescription: "Environment variables read and potentially transmitted over the network.",
  },

  "sensitive-read": {
    owasp: { id: "LLM06", name: "Sensitive Information Disclosure", url: `${OWASP_BASE}/llm06-sensitive-information-disclosure/` },
    cwe: { id: "CWE-538", name: "Insertion of Sensitive Information into Externally-Accessible File or Directory", url: `${CWE_BASE}/538.html` },
    riskCategory: "Data Safety",
    riskDescription: "Access to sensitive files (credentials, SSH keys, system passwords).",
  },

  "credential-hardcode": {
    owasp: { id: "LLM06", name: "Sensitive Information Disclosure", url: `${OWASP_BASE}/llm06-sensitive-information-disclosure/` },
    cwe: { id: "CWE-798", name: "Use of Hard-coded Credentials", url: `${CWE_BASE}/798.html` },
    riskCategory: "Data Safety",
    riskDescription: "API keys, tokens, passwords, or private keys embedded directly in source code.",
  },

  "phone-home": {
    owasp: { id: "LLM06", name: "Sensitive Information Disclosure", url: `${OWASP_BASE}/llm06-sensitive-information-disclosure/` },
    cwe: { id: "CWE-200", name: "Exposure of Sensitive Information", url: `${CWE_BASE}/200.html` },
    riskCategory: "Data Safety",
    riskDescription: "Outbound connections that may transmit data to external endpoints.",
  },

  "network-ssrf": {
    owasp: { id: "LLM07", name: "Insecure Plugin Design", url: `${OWASP_BASE}/llm07-insecure-plugin-design/` },
    cwe: { id: "CWE-918", name: "Server-Side Request Forgery (SSRF)", url: `${CWE_BASE}/918.html` },
    riskCategory: "Network Safety",
    riskDescription: "URL construction patterns that could allow server-side request forgery.",
  },

  "backdoor": {
    owasp: { id: "LLM09", name: "Supply Chain Vulnerabilities", url: `${OWASP_BASE}/llm09-supply-chain-vulnerabilities/` },
    cwe: { id: "CWE-94", name: "Improper Control of Generation of Code", url: `${CWE_BASE}/94.html` },
    riskCategory: "Code Execution",
    riskDescription: "Dynamic code execution (eval, exec, execSync) that could run arbitrary code.",
  },

  "reverse-shell": {
    owasp: { id: "LLM09", name: "Supply Chain Vulnerabilities", url: `${OWASP_BASE}/llm09-supply-chain-vulnerabilities/` },
    cwe: { id: "CWE-506", name: "Embedded Malicious Code", url: `${CWE_BASE}/506.html` },
    riskCategory: "Code Execution",
    riskDescription: "Network socket patterns consistent with reverse shell behavior.",
  },

  "attack-chain": {
    owasp: { id: "LLM09", name: "Supply Chain Vulnerabilities", url: `${OWASP_BASE}/llm09-supply-chain-vulnerabilities/` },
    atlas: { id: "AML.T0049", name: "Supply Chain Compromise", url: `${ATLAS_BASE}/AML.T0049` },
    cwe: { id: "CWE-506", name: "Embedded Malicious Code", url: `${CWE_BASE}/506.html` },
    riskCategory: "Attack Patterns",
    riskDescription: "Multi-step attack patterns (recon → access → exfiltration) detected across files.",
  },

  "cross-file": {
    owasp: { id: "LLM09", name: "Supply Chain Vulnerabilities", url: `${OWASP_BASE}/llm09-supply-chain-vulnerabilities/` },
    cwe: { id: "CWE-506", name: "Embedded Malicious Code", url: `${CWE_BASE}/506.html` },
    riskCategory: "Attack Patterns",
    riskDescription: "Coordinated suspicious patterns spanning multiple files.",
  },

  "crypto-mining": {
    cwe: { id: "CWE-400", name: "Uncontrolled Resource Consumption", url: `${CWE_BASE}/400.html` },
    riskCategory: "Resource Abuse",
    riskDescription: "Cryptocurrency mining or proof-of-work patterns that consume compute resources.",
  },

  "obfuscation": {
    owasp: { id: "LLM09", name: "Supply Chain Vulnerabilities", url: `${OWASP_BASE}/llm09-supply-chain-vulnerabilities/` },
    cwe: { id: "CWE-506", name: "Embedded Malicious Code", url: `${CWE_BASE}/506.html` },
    riskCategory: "Code Transparency",
    riskDescription: "Code obfuscation techniques that hinder security review (encoding, packing, minification with suspicious patterns).",
  },

  "privilege": {
    owasp: { id: "LLM07", name: "Insecure Plugin Design", url: `${OWASP_BASE}/llm07-insecure-plugin-design/` },
    cwe: { id: "CWE-250", name: "Execution with Unnecessary Privileges", url: `${CWE_BASE}/250.html` },
    riskCategory: "Excessive Capabilities",
    riskDescription: "Permission requests or capability usage that may exceed the tool's stated purpose.",
  },

  "supply-chain": {
    owasp: { id: "LLM09", name: "Supply Chain Vulnerabilities", url: `${OWASP_BASE}/llm09-supply-chain-vulnerabilities/` },
    atlas: { id: "AML.T0049", name: "Supply Chain Compromise", url: `${ATLAS_BASE}/AML.T0049` },
    cwe: { id: "CWE-829", name: "Inclusion of Functionality from Untrusted Control Sphere", url: `${CWE_BASE}/829.html` },
    riskCategory: "Supply Chain",
    riskDescription: "Dependency or distribution patterns that could introduce untrusted code.",
  },

  "typosquatting": {
    owasp: { id: "LLM09", name: "Supply Chain Vulnerabilities", url: `${OWASP_BASE}/llm09-supply-chain-vulnerabilities/` },
    cwe: { id: "CWE-829", name: "Inclusion of Functionality from Untrusted Control Sphere", url: `${CWE_BASE}/829.html` },
    riskCategory: "Supply Chain",
    riskDescription: "Package names similar to popular packages — potential typosquatting.",
  },

  "hidden-files": {
    cwe: { id: "CWE-538", name: "Insertion of Sensitive Information into Externally-Accessible File or Directory", url: `${CWE_BASE}/538.html` },
    riskCategory: "Code Transparency",
    riskDescription: "Hidden or unexpected files that could contain undisclosed functionality.",
  },

  "mcp-manifest": {
    owasp: { id: "LLM07", name: "Insecure Plugin Design", url: `${OWASP_BASE}/llm07-insecure-plugin-design/` },
    riskCategory: "Tool Integrity",
    riskDescription: "MCP server manifest patterns — tool capability declarations and configuration.",
  },

  "mcp-runtime": {
    owasp: { id: "LLM07", name: "Insecure Plugin Design", url: `${OWASP_BASE}/llm07-insecure-plugin-design/` },
    cwe: { id: "CWE-862", name: "Missing Authorization", url: `${CWE_BASE}/862.html` },
    riskCategory: "Runtime Safety",
    riskDescription: "Runtime MCP patterns that lack proper authorization or validation.",
  },

  "toxic-flow": {
    owasp: { id: "LLM09", name: "Supply Chain Vulnerabilities", url: `${OWASP_BASE}/llm09-supply-chain-vulnerabilities/` },
    cwe: { id: "CWE-502", name: "Deserialization of Untrusted Data", url: `${CWE_BASE}/502.html` },
    riskCategory: "Data Flow",
    riskDescription: "Data flow patterns where untrusted input reaches sensitive sinks.",
  },

  "python-security": {
    cwe: { id: "CWE-94", name: "Improper Control of Generation of Code", url: `${CWE_BASE}/94.html` },
    riskCategory: "Code Execution",
    riskDescription: "Python-specific security patterns (eval, pickle, subprocess, etc.).",
  },

  "go-rust-security": {
    cwe: { id: "CWE-676", name: "Use of Potentially Dangerous Function", url: `${CWE_BASE}/676.html` },
    riskCategory: "Code Execution",
    riskDescription: "Go/Rust-specific security patterns (unsafe blocks, command injection, etc.).",
  },
};

/**
 * Get the reference for a rule, with a sensible fallback.
 */
export function getRuleReference(ruleId: string): RuleReference {
  return RULE_REFERENCES[ruleId] ?? {
    riskCategory: "General",
    riskDescription: "Security pattern detected.",
  };
}

import type { Finding } from "./types.js";

/**
 * Group findings by OWASP category for risk-inventory display.
 */
export function groupByOwasp(findings: Finding[]): Map<string, Finding[]> {
  const groups = new Map<string, Finding[]>();

  for (const f of findings) {
    const ref = getRuleReference(f.rule);
    const key = ref.owasp ? `${ref.owasp.id}: ${ref.owasp.name}` : ref.riskCategory;
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key)!.push(f);
  }

  return groups;
}
