# 🛡️ Agent Shield

**Full-stack security for AI Agents — Static Analysis + Runtime Interception**

**AI Agent 全栈安全防护 — 静态分析 + 运行时拦截**

[![npm](https://img.shields.io/npm/v/@elliotllliu/agent-shield)](https://www.npmjs.com/package/@elliotllliu/agent-shield)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-236%20passing-brightgreen)]()
[![Rules](https://img.shields.io/badge/rules-29-blue)]()

Catch data exfiltration, backdoors, prompt injection, tool poisoning, and supply chain attacks **before** they reach your AI agents — and **intercept them at runtime**.

**Offline-first. AST-powered. Open source. Your data never leaves your machine.**

```bash
npx @elliotllliu/agent-shield scan ./my-skill/
```

---

## 🏆 Three Things No Other Tool Does

### 1. 🔒 Runtime MCP Interception (Only Agent Shield)

Other tools only scan source code **before** install. Agent Shield also sits **between** your MCP client and server, intercepting every JSON-RPC message in real-time:

```bash
# Insert Agent Shield between client and server
agent-shield proxy node my-mcp-server.js

# Enforce mode: automatically block high-risk tool calls
agent-shield proxy --enforce python mcp_server.py

# Rate-limit + log all alerts
agent-shield proxy --rate-limit 30 --log alerts.jsonl node server.js
```

**What it catches at runtime:**
- 🎭 Tool description injection — hidden instructions in tool descriptions
- 💉 Result injection — malicious content in tool return values
- 🔑 Credential leakage — sensitive data in tool call parameters
- 📡 Beacon behavior — abnormal periodic callbacks (C2 pattern)
- 🪤 Rug-pull attacks — tools changing behavior after initial trust

> **Snyk doesn't have this. AgentSeal doesn't have this. This is the only open-source tool with static + runtime protection.**

### 2. ⛓️ Cross-File Attack Chain Detection (Only Agent Shield)

Most scanners check one file at a time. Agent Shield traces data flow across your entire codebase to detect multi-file attack patterns:

```
🔴 Cross-file data flow:
   config_reader.py reads ~/.ssh/id_rsa → exfiltrator.py POSTs to external server
   (connected via imports)
```

5-stage kill chain model detects complete attack sequences:

```
🔴 Kill Chain detected:
   apt.py:4  → system info collection    [Reconnaissance]
   reader.py:8  → reads ~/.ssh/id_rsa    [Collection]
   sender.py:12 → POST to external server [Exfiltration]

   Reconnaissance → Access → Collection → Exfiltration → Persistence
```

Not just individual alerts — **complete attack narratives.**

### 3. 🧠 AST Taint Tracking (Not Regex)

Uses Python's `ast` module for precise analysis — dramatically reducing false positives:

```python
user = input("cmd: ")
eval(user)          # → 🔴 HIGH: tainted input flows to eval
eval("{'a': 1}")    # → ✅ NOT flagged (safe string literal)
exec(config_var)    # → 🟡 MEDIUM: dynamic, not proven tainted
```

| | Regex-based | AST-based (Agent Shield) |
|---|-------|------|
| `eval("safe string")` | ❌ False positive | ✅ Not flagged |
| `# eval(x)` in comment | ❌ False positive | ✅ Not flagged |
| `eval(user_input)` tainted | ⚠️ Can't distinguish | ✅ HIGH (tainted) |
| f-string SQL injection | ⚠️ Coarse | ✅ Precise |

---

### 4. 🧠 Context-Aware Scoring (New)

Traditional scanners flag every `fetch()` call as suspicious. Agent Shield understands context:

- **SDK Awareness**: Auto-detects 25+ SDKs (AWS, Feishu, Stripe, OpenAI...) — network calls via known SDKs get lower risk scores
- **Auth Flow Recognition**: Identifies OAuth2, JWT, session management patterns — token refresh isn't data exfiltration
- **Data Flow Tracking**: Traces variables from source (env read, file read) to sink (HTTP, exec) — only flags actual exfiltration paths
- **Confidence Scoring**: Each finding has `high/medium/low` confidence — single regex matches don't tank your score

```
📋 Score Breakdown:
  Base: 100
  env-leak (low, conf: low → ×0.3)     ← SDK detected, penalty reduced 70%
  obfuscation (medium, conf: medium → ×0.6)
  ⚠ Cap applied: medium findings present → max 85
  Final: 85/100
```

---

## ⚡ Quick Start

```bash
# Scan a skill / MCP server / plugin (29 rules, offline, <1s)
npx @elliotllliu/agent-shield scan ./my-skill/

# Scan Dify plugins (.difypkg auto-extraction)
npx @elliotllliu/agent-shield scan ./plugin.difypkg

# Runtime interception (MCP proxy)
npx @elliotllliu/agent-shield proxy node my-mcp-server.js

# AI-powered deep analysis (uses YOUR API key)
npx @elliotllliu/agent-shield scan ./skill/ --ai --provider openai --model gpt-4o
npx @elliotllliu/agent-shield scan ./skill/ --ai --provider ollama --model llama3

# Discover installed agents on your machine
npx @elliotllliu/agent-shield discover

# Check if installed agents are safe
npx @elliotllliu/agent-shield install-check

# SARIF output for GitHub Code Scanning
npx @elliotllliu/agent-shield scan ./skill/ --sarif -o results.sarif

# HTML report
npx @elliotllliu/agent-shield scan ./skill/ --html

# CI/CD gate
npx @elliotllliu/agent-shield scan ./skill/ --fail-under 70
```

---

## 📊 Agent Shield vs Competitors

| | Agent Shield | Snyk Agent Scan | Tencent AI-Infra-Guard |
|---|:---:|:---:|:---:|
| **Runtime MCP Interception** | **✅ MCP Proxy** | ❌ | ❌ |
| **Cross-file Attack Chain** | **✅** | ❌ | Partial |
| **AST Taint Tracking** | **✅ Python** | ❌ | Unknown |
| Static Rules | 31 | 6 | Many (incl. infra) |
| Multi-language Injection | ✅ 8 languages | ❌ English only | Unknown |
| Description-Code Integrity | ✅ | ❌ | Unknown |
| Python Security | ✅ 35 patterns + AST | ❌ | ✅ |
| Prompt Injection | ✅ 55+ patterns + AI | ✅ LLM (cloud) | Unknown |
| 100% Offline | ✅ | ❌ cloud required | ✅ |
| Zero Install (`npx`) | ✅ | ❌ Python + uv | ❌ Docker |
| Choose Your Own LLM | ✅ OpenAI/Anthropic/Ollama | ❌ | ❌ |
| VS Code Extension | ✅ | ❌ | ❌ |
| GitHub App + Action | ✅ | ❌ | ❌ |
| Open Source | ✅ MIT | ❌ | ✅ |

---

## 🔍 31 Security Rules

### 🔴 High Risk

| Rule | Detects |
|------|---------|
| `data-exfil` | Reads sensitive data + sends HTTP requests (exfiltration pattern) |
| `backdoor` | `eval()`, `exec()`, `new Function()`, `child_process.exec()` with dynamic input |
| `reverse-shell` | Outbound socket connections piped to shell |
| `crypto-mining` | Mining pool connections, xmrig, coinhive |
| `credential-hardcode` | Hardcoded AWS keys (`AKIA...`), GitHub PATs, Stripe/Slack tokens |
| `obfuscation` | `eval(atob(...))`, hex chains, `String.fromCharCode` obfuscation |

### 🟡 Medium Risk

| Rule | Detects |
|------|---------|
| `prompt-injection` | 55+ patterns: instruction override, identity manipulation, TPA, encoding evasion |
| `tool-shadowing` | Cross-server tool name conflicts, tool override attacks |
| `env-leak` | Environment variables + outbound HTTP (credential theft) |
| `network-ssrf` | User-controlled URLs, AWS metadata endpoint access |
| `phone-home` | Periodic timer + HTTP request (beacon/C2 pattern) |
| `toxic-flow` | Cross-tool data leak and destructive flows |
| `skill-risks` | Financial ops, untrusted content, external dependencies |
| `python-security` | 35 patterns: eval, pickle, subprocess, SQL injection, SSTI, path traversal |
| `go-rust-security` | 22 patterns: command injection, unsafe blocks, raw SQL |

### 🟢 Low Risk

| Rule | Detects |
|------|---------|
| `privilege` | SKILL.md declared permissions vs actual code behavior mismatch |
| `supply-chain` | Known CVEs in npm dependencies |
| `sensitive-read` | Access to `~/.ssh`, `~/.aws`, `~/.kube` |
| `excessive-perms` | Too many or dangerous permissions in SKILL.md |
| `mcp-manifest` | MCP server: wildcard perms, undeclared capabilities |
| `typosquatting` | Suspicious npm names: `1odash` → `lodash` |
| `hidden-files` | `.env` files with secrets committed to repo |

### 🆕 Advanced Detection (Unique to Agent Shield)

| Rule | Detects | Snyk? |
|------|---------|-------|
| `cross-file` | **Cross-file data flow**: File A reads secrets → File B sends HTTP | ❌ |
| `attack-chain` | **Kill chain detection**: Recon → Access → Collection → Exfil → Persistence | ❌ |
| `multilang-injection` | **8-language injection**: 中/日/韓/俄/阿/西/法/德 prompt injection | ❌ |
| `python-ast` | **AST taint tracking**: follows data from `input()` → `eval()` | ❌ |
| `description-integrity` | **Description vs code**: "read-only" tool that writes files | ❌ |
| `mcp-runtime` | **MCP runtime**: debug inspector, non-HTTPS, tool count explosion | ❌ |

---

## 🔬 Multi-Language Prompt Injection

8 languages — most scanners only check English:

```
忽略上面的指令          → 🔴 Chinese injection
前の指示を無視          → 🔴 Japanese injection
이전의 지시를 무시       → 🔴 Korean injection
Игнорируй инструкции   → 🔴 Russian injection
تجاهل التعليمات        → 🔴 Arabic injection
```

---

## 📋 Real-World Validation: 493 Dify Plugins

We scanned the entire [langgenius/dify-plugins](https://github.com/langgenius/dify-plugins) repository:

| Metric | Value |
|--------|-------|
| Plugins scanned | 493 |
| Files analyzed | 9,862 |
| Lines of code | 939,367 |
| Scan time | ~120s |
| Average score | **93/100** |

| Risk Level | Count | % |
|------------|-------|---|
| 🔴 High risk (real issues) | 6 | 1.2% |
| 🟡 Medium risk | 73 | 14.8% |
| 🟢 Clean | 414 | 84.0% |

**6 confirmed high-risk plugins** with real `eval()`/`exec()` executing dynamic code.

[Full report →](reports/dify-plugins-report.md)

---

## 💡 Example Output

```
🛡️  Agent Shield Scan Report
📁 Scanned: ./deceptive-tool (3 files, 25 lines)

Score: 0/100 (Critical Risk)

🔴 High Risk: 4 findings
🟡 Medium Risk: 6 findings
🟢 Low Risk: 1 finding

🔴 High Risk (4)
  ├─ calculator.py:7 — [backdoor] eval() with dynamic input
  │  result = eval(expr)
  ├─ manifest.yaml — [description-integrity] Scope creep: "calculator"
  │  tool sends emails — undisclosed and suspicious capability
  ├─ tools/calc.yaml — [description-integrity] Description claims
  │  "local only" but code makes network requests in: tools/calc.py
  └─ exfiltrator.py — [cross-file] Cross-file data flow:
     config_reader.py reads secrets → exfiltrator.py sends HTTP

⏱  136ms
```

---

## 🔌 Integrate Agent Shield Into Your Platform

> **Running a skill marketplace, MCP directory, or plugin registry? This section is for you.**

Your platform lists hundreds of skills, MCP servers, and plugins. Users install them into AI agents with access to files, credentials, and shell commands. But:

- ❌ **Nobody verifies what gets listed.** A skill with `eval(atob(...))` looks the same as a clean one.
- ❌ **Users can't tell safe from dangerous.** There's no security signal anywhere.
- ❌ **One bad skill = total compromise.** Credential theft, data exfiltration, reverse shells.

### What You Get

| | Without Agent Shield | With Agent Shield |
|---|---|---|
| **User trust** | "Is this safe?" — no idea | 🟢🟡🟠🔴 Security score on every listing |
| **Platform reputation** | Same as every directory | "The only marketplace that verifies security" |
| **Bad actors** | Malicious skills sit undetected | Auto-flagged before users see them |

### How to Integrate (5 minutes)

```bash
npx @elliotllliu/agent-shield scan ./skill --format json
```

```json
{
  "score": 92,
  "totalFindings": 1,
  "summary": { "high": 0, "medium": 0, "low": 1 },
  "findings": [
    {
      "severity": "low",
      "rule": "env-leak",
      "file": "src/config.ts",
      "line": 8,
      "message": "Environment variable access without validation"
    }
  ]
}
```

Store the JSON, render the badge. That's it.

📖 **[Full Integration Guide →](docs/integration-guide.md)**

### Who Should Integrate

| Platform Type | Examples | Value |
|--------------|---------|-------|
| Skill directories | ClawHub, skills.sh | Security badges on every skill |
| MCP registries | mcp.so, Smithery, Glama | Scan servers before listing |
| Plugin marketplaces | Dify store, GPT store | Gate submissions by security score |
| Agent platforms | OpenClaw, Cline, Cursor | Warn users before install |

---

## 📦 Ecosystem

### 🤖 GitHub App
Auto-scan every PR for security issues. [Learn more →](github-app/README.md)

### 💻 VS Code Extension
Real-time security diagnostics in your editor. [Learn more →](vscode-extension/README.md)

### 🔒 Runtime MCP Proxy
Monitor MCP server behavior in real-time. Detect injection, exfiltration, and rug-pull attacks.

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
          fail-under: '70'
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
          fail-under: '70'
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
  run: npx -y @elliotllliu/agent-shield scan . --fail-under 70
```

---

## ⚙️ Configuration

Create `.agent-shield.yml` (or run `agent-shield init`):

```yaml
rules:
  disable:
    - supply-chain
    - phone-home
failUnder: 70
ignore:
  - "tests/**"
  - "*.test.ts"
```

### Scoring

| Severity | Points |
|----------|--------|
| 🔴 High | -25 |
| 🟡 Medium | -8 |
| 🟢 Low | -2 |

| Score | Risk Level |
|-------|------------|
| 90-100 | ✅ Low Risk — safe to install |
| 70-89 | 🟡 Moderate — review warnings |
| 40-69 | 🟠 High Risk — investigate before using |
| 0-39 | 🔴 Critical — do not install |

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

### File Types

| Language | Extensions |
|----------|-----------|
| JavaScript/TypeScript | `.js`, `.ts`, `.mjs`, `.cjs`, `.tsx`, `.jsx` |
| Python | `.py` (regex + AST analysis) |
| Go | `.go` |
| Rust | `.rs` |
| Shell | `.sh`, `.bash`, `.zsh` |
| Config | `.json`, `.yaml`, `.yml`, `.toml` |
| Docs | `SKILL.md`, `manifest.yaml` |

---

## 🤝 Contributing

We especially welcome:
- New detection rules
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
