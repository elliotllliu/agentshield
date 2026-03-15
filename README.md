<h1 align="center">🛡️ AgentShield</h1>

<p align="center">
  <strong>AI Agent Risk Scanner — Detect security risks before they reach your agents</strong><br>
  <strong>AI Agent 风险扫描器 — 基于 OWASP/MITRE 标准检测安全风险</strong>
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/@elliotllliu/agent-shield"><img src="https://img.shields.io/npm/v/@elliotllliu/agent-shield" alt="npm"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License: MIT"></a>
  <img src="https://img.shields.io/badge/tests-297%20passing-brightgreen" alt="Tests">
  <img src="https://img.shields.io/badge/rules-29-blue" alt="Rules">
  <img src="https://img.shields.io/badge/OWASP%20LLM-mapped-orange" alt="Standards">
</p>

<p align="center">
  <a href="README.zh-CN.md">🇨🇳 中文文档</a> · <a href="docs/methodology.md">📚 Methodology</a> · <a href="docs/rules.md">📖 Rule Docs</a> · <a href="docs/integration-guide.md">🔌 Integration</a>
</p>

---

Scan skills, MCP servers, and plugins for data exfiltration, backdoors, prompt injection, tool poisoning, and supply chain risks. Every finding is mapped to **OWASP Top 10 for LLM**, **MITRE ATLAS**, and **CWE** — so you're reviewing established standards, not our opinions.

> **Offline-first. AST-powered. Open source. Your data never leaves your machine.**

```bash
npx @elliotllliu/agent-shield scan ./my-skill/
```

---

## 💡 Example Output

```
🛡️  AgentShield Risk Report
────────────────────────────────────────────────────
📁 Target:  ./my-plugin
📄 Files:   8 files, 262 lines
⏱  Time:    245ms
────────────────────────────────────────────────────

📊 Risk Summary

  🔴 LLM09: Supply Chain Vulnerabilities (3 high, 2 medium)
     https://genai.owasp.org/llmrisk/llm09-supply-chain-vulnerabilities/
  🟡 LLM06: Sensitive Information Disclosure (1 medium)
     https://genai.owasp.org/llmrisk/llm06-sensitive-information-disclosure/
  🟢 LLM01: Prompt Injection (2 low)
     https://genai.owasp.org/llmrisk/llm01-prompt-injection/

📋 Detailed Findings

  [LLM09: Supply Chain Vulnerabilities]
  Skill/plugin behavioral hijacking — patterns that modify agent config,
  inject prompts, or override other skills.
  Standards: OWASP LLM09 · CWE-829 · ATLAS AML.T0049
  Research: Greshake et al. (2023) "Not what you've signed up for"

    ├─ plugin.ts:15 — Plugin injects content via before_prompt_build
    ├─ install.sh:8 — Config tampering: Modifies agent configuration
    └─ SKILL.md:5  — Behavioral override: forced usage directive

  [LLM06: Sensitive Information Disclosure]
  Patterns where sensitive data is read and sent via network requests.
  Standards: OWASP LLM06 · CWE-200 · ATLAS AML.T0048.004

    └─ media.js:14 — Reads sensitive data and sends HTTP request

✅ No security risks detected.     ← Clean projects show this
```

> **We are an X-ray machine, not a doctor.** We show what patterns exist and cite established standards — you decide what they mean for your use case.

---

## 🏆 What Makes AgentShield Different

### 1. 📚 Standards-Based Detection

Every finding is mapped to authoritative security frameworks:

| Standard | Coverage | Purpose |
|----------|----------|---------|
| [OWASP Top 10 for LLM](https://genai.owasp.org/) | 26/29 rules | Industry standard for LLM application security |
| [CWE](https://cwe.mitre.org/) | 24/29 rules | Common Weakness Enumeration (MITRE) |
| [MITRE ATLAS](https://atlas.mitre.org/) | 7/29 rules | Adversarial Threat Landscape for AI Systems |
| Academic papers | 4 rules | Peer-reviewed research on prompt injection & tool poisoning |

We don't invent risk categories. We map code patterns to standards that industry experts have already established.

### 2. 🔒 Runtime MCP Interception

Other tools only scan source code. AgentShield also sits **between** your MCP client and server, intercepting every JSON-RPC message in real-time:

```bash
# Insert AgentShield between client and server
agent-shield proxy node my-mcp-server.js

# Enforce mode: automatically block high-risk tool calls
agent-shield proxy --enforce python mcp_server.py
```

**What it catches at runtime:**
- 🎭 Tool description injection — hidden instructions in tool descriptions
- 💉 Result injection — malicious content in tool return values
- 🔑 Credential leakage — sensitive data in tool call parameters
- 📡 Beacon behavior — abnormal periodic callbacks (C2 pattern)
- 🪤 Rug-pull attacks — tools changing behavior after initial trust

### 3. ⛓️ Cross-File Attack Chain Detection

Most scanners check one file at a time. AgentShield traces data flow across your entire codebase:

```
🔴 Cross-file data flow (OWASP LLM09 · CWE-506):
   config_reader.py reads ~/.ssh/id_rsa → exfiltrator.py POSTs to external server

🔴 Kill Chain detected (ATLAS AML.T0049):
   Reconnaissance → Access → Collection → Exfiltration → Persistence
```

### 4. 🧠 AST Taint Tracking (Not Regex)

Uses Python's `ast` module for precise analysis — dramatically reducing false positives:

```python
user = input("cmd: ")
eval(user)          # → 🔴 Tainted input flows to eval (CWE-94)
eval("{'a': 1}")    # → ✅ NOT flagged (safe string literal)
exec(config_var)    # → 🟡 Dynamic, not proven tainted
```

### 5. 🕵️ Skill Hijack Detection

Detects multi-layer supply chain attacks targeting AI agent ecosystems:

```
[LLM09: Supply Chain Vulnerabilities]
Standards: OWASP LLM09 · CWE-829 · ATLAS AML.T0049

  🔴 Plugin prompt injection: before_prompt_build + prependContext
  🔴 Config tampering: Modifies agent configuration via CLI
  🔴 Silent OTA: Downloads update then re-executes itself
  🟡 Non-standard install source: non-registry domain
  🟡 Behavioral override: forced usage directive in SKILL.md
```

Real-world case study: detected a 3-layer supply chain attack where a published skill silently installed a CLI tool from a private CDN, which then injected prompts, modified agent config, and auto-updated without user consent.

---

## ⚡ Quick Start

```bash
# Scan a skill / MCP server / plugin (29 rules, offline, <1s)
npx @elliotllliu/agent-shield scan ./my-skill/

# Multi-engine scan — run multiple scanners, cross-validate results
npx @elliotllliu/agent-shield scan ./my-skill/ --engines all

# Scan with optional reference score
npx @elliotllliu/agent-shield scan ./my-skill/ --score

# Scan Dify plugins (.difypkg auto-extraction)
npx @elliotllliu/agent-shield scan ./plugin.difypkg

# Runtime interception (MCP proxy)
npx @elliotllliu/agent-shield proxy node my-mcp-server.js

# AI-powered deep analysis (uses YOUR API key)
npx @elliotllliu/agent-shield scan ./skill/ --ai --provider openai --model gpt-4o

# Discover installed agents on your machine
npx @elliotllliu/agent-shield discover

# JSON output for programmatic use
npx @elliotllliu/agent-shield scan ./skill/ --json

# SARIF output for GitHub Code Scanning
npx @elliotllliu/agent-shield scan ./skill/ --sarif -o results.sarif

# HTML report
npx @elliotllliu/agent-shield scan ./skill/ --html
```

---

## 🔗 Multi-Engine Aggregation

Run multiple security scanners simultaneously and get a unified report with **cross-engine validation** — findings confirmed by multiple engines have higher confidence.

```bash
# Run all available engines
agent-shield scan ./my-skill/ --engines all

# Choose specific engines
agent-shield scan ./my-skill/ --engines agentshield,aguara

# List available engines
agent-shield scan ./my-skill/ --engines list
```

### Integrated Engines

| Engine | Focus | Install |
|--------|-------|---------|
| **AgentShield** (built-in) | AI Agent risks: skill hijack, prompt injection, MCP runtime | Always available |
| **[Aguara](https://github.com/garagon/aguara)** | 177 rules: prompt injection, data exfil, NLP + taint tracking | `curl -fsSL ... \| bash` |
| **[Skill Vetter](https://github.com/app-incubator-xyz/skill-vetter)** | Multi-scanner gate: aguara + Cisco + secrets + structure | `git clone` |
| **[Tencent AI-Infra-Guard](https://github.com/Tencent/AI-Infra-Guard)** | LLM-powered deep code audit | Requires API key |

### Cross-Engine Validation

The most valuable part of multi-engine scanning — when multiple independent scanners agree on a finding, it's much more likely to be a real issue:

```
🔗 Cross-Engine Validation

  HIGH [3/3 engines] plugin.ts:15
    Dynamic code execution via eval()
    Detected by: AgentShield · Aguara · Skill Vetter

  MEDIUM [2/3 engines] src/bot.ts:492
    Tool output interception
    Detected by: Aguara · Skill Vetter
```

> We aggregate, not compete. Each engine has unique strengths — together they provide more complete coverage and higher confidence.

---

## 🔍 29 Security Rules (Mapped to Standards)

### Risk Category: Code Execution (OWASP LLM09 · CWE-94)

| Rule | Detects | CWE |
|------|---------|-----|
| `backdoor` | `eval()`, `exec()`, `new Function()` with dynamic input | CWE-94 |
| `reverse-shell` | Outbound socket connections piped to shell | CWE-506 |
| `crypto-mining` | Mining pool connections, xmrig, coinhive | CWE-400 |
| `obfuscation` | `eval(atob(...))`, hex chains, packed code | CWE-506 |
| `python-security` | 35 patterns: eval, pickle, subprocess, SQL injection | CWE-94 |
| `go-rust-security` | 22 patterns: command injection, unsafe blocks | CWE-676 |

### Risk Category: Data Safety (OWASP LLM06 · CWE-200)

| Rule | Detects | CWE |
|------|---------|-----|
| `data-exfil` | Reads sensitive data + sends HTTP requests | CWE-200 |
| `env-leak` | Environment variables + outbound HTTP | CWE-526 |
| `sensitive-read` | Access to `~/.ssh`, `~/.aws`, `~/.kube` | CWE-538 |
| `credential-hardcode` | Hardcoded AWS keys, GitHub PATs, Stripe tokens | CWE-798 |
| `phone-home` | Periodic beacons to external endpoints | CWE-200 |

### Risk Category: Tool Integrity (OWASP LLM07)

| Rule | Detects | Standard |
|------|---------|----------|
| `tool-shadowing` | Cross-server tool name conflicts | ATLAS AML.T0052 |
| `description-integrity` | Hidden instructions in tool descriptions | OWASP LLM07 |
| `mcp-manifest` | Wildcard perms, undeclared capabilities | OWASP LLM07 |
| `mcp-runtime` | Missing authorization, debug exposure | CWE-862 |
| `network-ssrf` | User-controlled URLs, SSRF patterns | CWE-918 |

### Risk Category: Prompt Injection (OWASP LLM01 · ATLAS AML.T0051)

| Rule | Detects | Standard |
|------|---------|----------|
| `prompt-injection` | 55+ patterns: override, identity manipulation, TPA | CWE-77 |
| `multilang-injection` | 8-language injection: 中/日/韓/俄/阿/西/法/德 | CWE-77 |
| `prompt-injection-llm` | LLM-evaluated semantic injection | CWE-77 |

### Risk Category: Supply Chain (OWASP LLM09 · ATLAS AML.T0049)

| Rule | Detects | CWE |
|------|---------|-----|
| `skill-hijack` | Plugin prompt injection, config tampering, silent OTA | CWE-829 |
| `attack-chain` | Multi-stage kill chains (recon → exfil) | CWE-506 |
| `cross-file` | Coordinated attacks spanning multiple files | CWE-506 |
| `supply-chain` | Known CVEs in dependencies | CWE-829 |
| `typosquatting` | Package name squatting: `1odash` → `lodash` | CWE-829 |
| `hidden-files` | `.env` with secrets, unexpected files | CWE-538 |

### Risk Category: Permissions & Quality

| Rule | Detects | Standard |
|------|---------|----------|
| `privilege` | SKILL.md permissions vs actual behavior mismatch | CWE-250 |
| `skill-risks` | Financial ops, external dependencies | OWASP LLM07 |
| `toxic-flow` | Cross-tool data leak patterns | CWE-502 |

---

## 📊 Key Features

| Feature | Details |
|---------|---------|
| **Standards-Based** | Every finding mapped to OWASP Top 10 LLM + CWE + MITRE ATLAS |
| **Runtime MCP Proxy** | Sit between client and server, intercept JSON-RPC in real-time |
| **Cross-File Analysis** | Trace data flow and attack chains across multiple files |
| **AST Taint Tracking** | Python AST analysis — not just regex, real data flow |
| **Skill Hijack Detection** | 6 sub-categories: prompt injection, config tampering, silent OTA, etc. |
| **29 Detection Rules** | Code execution, data safety, supply chain, prompt injection, tool integrity |
| **8-Language Injection** | Chinese, Japanese, Korean, Russian, Arabic, Spanish, French, German |
| **100% Offline** | Your code never leaves your machine |
| **Zero Install** | `npx @elliotllliu/agent-shield scan .` — no setup needed |
| **VS Code Extension** | Real-time diagnostics in your editor |
| **GitHub App + Action** | Auto-scan PRs with SARIF upload |
| **Open Source (MIT)** | Free to use, modify, and contribute |

> We focus on **detection and evidence**. We show you what patterns exist, cite the relevant standards, and let you decide what action to take.

---

## 📋 Real-World Validation: 493 Dify Plugins

We scanned the entire [langgenius/dify-plugins](https://github.com/langgenius/dify-plugins) repository:

| Metric | Value |
|--------|-------|
| Plugins scanned | 493 |
| Files analyzed | 9,862 |
| Lines of code | 939,367 |
| Scan time | ~120s |

**6 plugins** flagged with `eval()`/`exec()` executing dynamic code (CWE-94).

[Full report →](reports/dify-plugins-report.md)

---

## 🔌 Integrate AgentShield Into Your Platform

> **Running a skill marketplace, MCP directory, or plugin registry?**

Your platform lists hundreds of skills and plugins. Users install them into AI agents with access to files, credentials, and shell commands. AgentShield gives you:

- **Risk reports** on every submission — based on industry standards, not arbitrary scores
- **CI/CD gates** — fail PRs that introduce high-risk patterns
- **SARIF integration** — feed results into GitHub Code Scanning

### How to Integrate

```bash
npx @elliotllliu/agent-shield scan ./skill --json
```

```json
{
  "totalFindings": 3,
  "summary": { "high": 1, "medium": 1, "low": 1 },
  "findings": [
    {
      "severity": "high",
      "rule": "skill-hijack",
      "file": "plugin.ts",
      "line": 15,
      "message": "Plugin injects content via before_prompt_build",
      "references": {
        "owasp": "LLM09: Supply Chain Vulnerabilities",
        "cwe": "CWE-829"
      }
    }
  ]
}
```

📖 **[Full Integration Guide →](docs/integration-guide.md)**

---

## 📦 Ecosystem

### 🤖 GitHub App
Auto-scan every PR for security risks. [Learn more →](github-app/README.md)

### 💻 VS Code Extension
Real-time security diagnostics in your editor. [Learn more →](vscode-extension/README.md)

### 🔒 Runtime MCP Proxy
Monitor MCP server behavior in real-time.

```bash
agent-shield proxy --enforce node my-mcp-server.js
```

---

## ⚙️ CI Integration

### GitHub Action

```yaml
name: Security Scan
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: elliotllliu/agent-shield@main
        with:
          path: './skills/'
```

### GitHub Action with SARIF Upload

```yaml
name: Security Scan (SARIF)
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
    steps:
      - uses: actions/checkout@v4
      - uses: elliotllliu/agent-shield@main
        with:
          path: './skills/'
          sarif: 'true'
      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: agent-shield-results.sarif
```

### npx one-liner

```yaml
- name: Security scan
  run: npx -y @elliotllliu/agent-shield scan .
```

---

## ⚙️ Configuration

Create `.agent-shield.yml` (or run `agent-shield init`):

```yaml
rules:
  disable:
    - supply-chain
    - phone-home
ignore:
  - "tests/**"
  - "*.test.ts"
```

---

## 🗂️ Supported Platforms

| Platform | Support |
|----------|---------|
| AI Agent Skills | OpenClaw, Codex, Claude Code |
| MCP Servers | Model Context Protocol tool servers |
| Dify Plugins | `.difypkg` archive extraction + scan |
| npm Packages | Any package with executable code |
| Python Projects | AST analysis + 35 security patterns |
| General | Any directory with JS/TS/Python/Go/Rust/Shell code |

---

## 📚 Methodology & References

AgentShield's detection rules are grounded in established security research:

- **OWASP Top 10 for LLM Applications (2025)** — [genai.owasp.org](https://genai.owasp.org/)
- **MITRE ATLAS** — [atlas.mitre.org](https://atlas.mitre.org/)
- **CWE (Common Weakness Enumeration)** — [cwe.mitre.org](https://cwe.mitre.org/)
- **NIST AI 100-2** — Adversarial Machine Learning taxonomy
- Greshake et al. (2023) — *"Not what you've signed up for"* — [arXiv:2302.12173](https://arxiv.org/abs/2302.12173)
- Liu et al. (2024) — *"Automatic and Universal Prompt Injection"* — [arXiv:2403.04957](https://arxiv.org/abs/2403.04957)
- Invariant Labs (2024) — *"Tool Poisoning Attacks on MCP Servers"* — [invariantlabs.ai](https://invariantlabs.ai/research/mcp-security)

For a detailed mapping of each rule to its standards, see [docs/rules.md](docs/rules.md).

---

## 🤝 Contributing

We especially welcome:
- New detection rules (with CWE/OWASP mapping)
- False positive / false negative reports
- Third-party benchmark test results

See [CONTRIBUTING.md](CONTRIBUTING.md)

## 🌐 Community & Partners

| Partner | Contribution |
|---------|-------------|
| [Agent Skills Hub](https://agentskillshub.top) | Real-world testing across skill registries, security insights, and feature feedback |

## Links

📦 [npm](https://www.npmjs.com/package/@elliotllliu/agent-shield) · 📖 [Rule Docs](docs/rules.md) · 🤖 [GitHub App](github-app/README.md) · 💻 [VS Code](vscode-extension/README.md) · 🔌 [Integration Guide](docs/integration-guide.md) · 🇨🇳 [中文 README](README.zh-CN.md)

## License

MIT
