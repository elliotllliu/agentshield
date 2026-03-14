# 🛡️ Agent Shield

**Lightweight open-source AI Agent security scanner — Static Analysis + Runtime Interception**

[![npm](https://img.shields.io/npm/v/@elliotllliu/agent-shield)](https://www.npmjs.com/package/@elliotllliu/agent-shield)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-236%20passing-brightgreen)]()
[![Rules](https://img.shields.io/badge/rules-29-blue)]()

> Free, offline, zero-config AI Agent security scanner.
> Quickly check your skills, MCP servers, and plugins for security issues.

```bash
npx @elliotllliu/agent-shield scan ./my-skill/
```

---

## 🏆 Key Features

### 1. 🔒 Runtime MCP Interception
Monitor MCP tool calls in real-time — not just static code scanning.

```bash
agent-shield proxy node my-mcp-server.js
agent-shield proxy --enforce python mcp_server.py
```

Detects: tool description injection, result injection, credential leaks, sensitive path access, behavioral anomalies.

### 2. ⛓️ Cross-File Attack Chain Detection
Tracks complete attack paths across multiple files.

### 3. 🆓 Free & Offline
No account · no code upload · no API key required · `npx` one-liner.

---

### 🧠 Context-Aware Scoring

- **SDK Awareness**: Auto-detects 25+ SDKs — network calls via known SDKs get lower risk scores
- **Auth Flow Recognition**: Identifies OAuth2, JWT, session management — legitimate auth isn't flagged as exfiltration
- **Data Flow Tracking**: Traces variables from source to sink — only flags actual exfiltration paths
- **Confidence Scoring**: `high/medium/low` confidence multipliers reduce false positive impact

---

## ⚡ Quick Start

```bash
npx @elliotllliu/agent-shield scan ./skill/      # Scan
npx @elliotllliu/agent-shield proxy node server.js # Runtime proxy
npx @elliotllliu/agent-shield install-check        # Check installed agents
```

---

## 📊 Positioning

Agent Shield is a **lightweight open-source tool** for quick security self-checks during development. It is not a replacement for enterprise security platforms.

| | Agent Shield | Snyk Agent Scan | Tencent AI-Infra-Guard |
|---|:---:|:---:|:---:|
| **Positioning** | Lightweight OSS tool | Commercial service | Enterprise red team |
| Runtime interception | ✅ MCP Proxy | ❌ | ❌ |
| Cross-file attack chain | ✅ | ❌ | Partial |
| Static rules | 31 | 6 | Many (incl. infra) |
| Offline/free | ✅ | ❌ Account required | ✅ Open source |
| Zero config | ✅ `npx` one-liner | ❌ Python+uv needed | ❌ Docker needed |
| Security team | ❌ Individual project | ✅ Snyk security team | ✅ Tencent labs |
| Vulnerability DB | ❌ | ✅ | ✅ |
| Enterprise support | ❌ | ✅ | ✅ Pro version |
| Production validated | ❌ Early stage | ✅ | ✅ Black Hat |
| VS Code / Action | ✅ | ❌ | ❌ |

**Good for:** Dev-stage quick checks · CI/CD lightweight gate · Runtime MCP monitoring
**Not for:** Enterprise compliance as sole tool

---

## 🔍 31 Security Rules

**🔴 High**: data-exfil · backdoor · reverse-shell · crypto-mining · credential-hardcode · obfuscation

**🟡 Medium**: prompt-injection (55+ patterns) · tool-shadowing · env-leak · network-ssrf · phone-home · toxic-flow · skill-risks · python-security (35 patterns) · go-rust-security (22 patterns)

**🟢 Low**: privilege · supply-chain · sensitive-read · excessive-perms · mcp-manifest · typosquatting · hidden-files

**Advanced**: cross-file · attack-chain · multilang-injection · python-ast · description-integrity · mcp-runtime

---

## 📈 Testing

**Benchmark**: 120 self-built samples, 100% F1. ⚠️ Not independently verified.

**Dify Plugins**: Scanned 493 plugins, found 6 true high-risk (`eval()`/`exec()`), 0 false positives at high severity.

---

## Usage

```bash
agent-shield scan ./skill/ [--json|--sarif|--html] [--fail-under 70] [--ai]
agent-shield proxy [--enforce] [--rate-limit N] <command>
agent-shield mcp-audit <command>
agent-shield discover
```

[GitHub Action](github-app/README.md) · [VS Code Extension](vscode-extension/README.md)

## Links

📦 [npm](https://www.npmjs.com/package/@elliotllliu/agent-shield) · 📖 [Rules](docs/rules.md) · 🇨🇳 [中文](README.md)

## 🌐 Community & Partners

| Partner | Contribution |
|---------|-------------|
| [Agent Skills Hub](https://agentskillshub.top) | Real-world testing across skill registries, security insights, and feature feedback |

## License
MIT
