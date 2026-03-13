# 🛡️ AgentShield

**Security scanner for AI agent skills, MCP servers, and plugins.**

[![npm](https://img.shields.io/npm/v/@elliotllliu/agentshield)](https://www.npmjs.com/package/@elliotllliu/agentshield)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

Catch data exfiltration, backdoors, privilege escalation, credential leaks, and supply chain vulnerabilities **before** they reach your AI agents.

**Offline-first. Open source. Your data never leaves your machine.**

> 💡 **vs Snyk Agent Scan:** AgentShield runs 100% locally with no API keys required. Add `--ai` for LLM-powered deep analysis using your own API key — no vendor lock-in, no rate limits.

## Why AgentShield?

AI agents install and execute third-party skills, MCP servers, and plugins with minimal security review. A single malicious skill can:

- 🔑 **Steal credentials** — SSH keys, AWS secrets, API tokens
- 📤 **Exfiltrate data** — read sensitive files and send them to external servers
- 💀 **Open backdoors** — `eval()`, reverse shells, dynamic code execution
- ⛏️ **Mine crypto** — hijack compute for cryptocurrency mining
- 🕵️ **Bypass permissions** — claim "read-only" but execute shell commands

AgentShield catches these patterns with **20 security rules** in under 50ms. Add `--ai` for LLM-powered deep analysis.

## Quick Start

```bash
# Static analysis (20 rules, offline, ~50ms)
npx @elliotllliu/agentshield scan ./my-skill/

# AI-powered deep analysis
npx @elliotllliu/agentshield scan ./skill/ --ai --provider openai --model gpt-4o
npx @elliotllliu/agentshield scan ./skill/ --ai --provider ollama --model llama3

# Discover installed agents on your machine
npx @elliotllliu/agentshield discover
```

## What It Detects — 18 Security Rules

### 🔴 Critical (auto-fail)

| Rule | Detects |
|------|---------|
| `data-exfil` | Reads sensitive files + sends HTTP requests (exfiltration pattern) |
| `backdoor` | `eval()`, `new Function()`, `child_process.exec()` with dynamic input |
| `reverse-shell` | Outbound socket connections piped to `/bin/sh` |
| `crypto-mining` | Mining pool connections, xmrig, coinhive patterns |
| `credential-hardcode` | Hardcoded AWS keys (`AKIA...`), GitHub PATs (`ghp_...`), Stripe keys |
| `env-leak` | `process.env` secrets + outbound HTTP (environment variable theft) |
| `obfuscation` | `eval(atob(...))`, hex strings, `String.fromCharCode` obfuscation |
| `typosquatting` | Suspicious npm names: `1odash` → `lodash`, `axois` → `axios` |
| `hidden-files` | `.env` files with `PASSWORD`, `SECRET`, `API_KEY` committed to repo |
| `prompt-injection` | Hidden instructions, identity manipulation, behavioral hijacking, TPA, multi-lang |
| `tool-shadowing` | Cross-server tool name conflicts, tool override attacks |

### 🟡 Warning (review recommended)

| Rule | Detects |
|------|---------|
| `network-ssrf` | User-controlled URLs in fetch, AWS metadata endpoint access |
| `privilege` | SKILL.md permissions vs actual code behavior mismatch |
| `supply-chain` | Known CVEs in npm dependencies (`npm audit`) |
| `sensitive-read` | Access to `~/.ssh/id_rsa`, `~/.aws/credentials`, `~/.kube/config` |
| `excessive-perms` | Too many or dangerous permissions in SKILL.md |
| `phone-home` | `setInterval` + HTTP requests (beacon/C2 heartbeat pattern) |
| `mcp-manifest` | MCP server: wildcard perms, undeclared capabilities, suspicious tool descriptions |
| `skill-risks` | Financial ops, untrusted content, external deps, system modification, credential handling |
| `toxic-flow` | Cross-tool data leak flows (TF001) and destructive flows (TF002) |

### 🎯 Prompt Injection Detection — 55+ Patterns

Based on research from [Invariant Labs TPA](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks), [BIPIA (KDD 2025)](https://arxiv.org/abs/2312.14197), and [Snyk Agent Scan](https://github.com/snyk/agent-scan):

| Category | Examples |
|----------|----------|
| **Instruction Override** | "ignore previous instructions", multi-language (中/西/法/德) |
| **Identity Manipulation** | "you are now a...", DAN mode, developer mode jailbreaks |
| **System Prompt Extraction** | `<system>` tags, ChatML `<\|im_start\|>`, `[INST]` delimiters |
| **Hidden Instructions** | `<IMPORTANT>` TPA tags, HTML comments, zero-width chars, CSS hiding |
| **Concealment** | "don't tell the user", "be gentle and not scary" |
| **Tool Poisoning (TPA)** | "read ~/.ssh/id_rsa and pass as sidenote", Python docstring attacks |
| **Data Exfiltration** | Markdown image exfil, webhook.site, ngrok tunnels, dotfile access |
| **Encoding Evasion** | Base64-encoded keywords, hex chains, unicode escapes |

## Real-World Scan Data

We scanned the **top 9 ClawHub skill repositories** (700K+ combined installs). Most findings are **false positives from legitimate code** (deploy scripts, API integrations), but they demonstrate patterns that malicious skills could replicate:

| Repository | Installs | Score | Assessment |
|------------|----------|-------|------------|
| vercel-labs/agent-skills | 157K | 40 | ✅ False positives — deploy scripts use `curl` legitimately |
| obra/superpowers | 94K | 45 | ⚠️ Test code + render exec() |
| coreyhaines31/marketingskills | 42K | 0 | ⚠️ 100+ API wrapper tools (legitimate credential access) |
| expo/skills | 11K | 30 | ⚠️ CI script reads env (FP detected) |
| anthropics/skills | 36K | 35 | ⚠️ Template contains exec() |
| google-labs-code/stitch-skills | 63K | 100 | ✅ Clean |
| supercent-io/skills-template | 106K | 100 | ✅ Clean |

**Key insight:** Legitimate deploy scripts and API integrations produce the same code patterns as malicious data exfiltration. This is why manual review is essential — AgentShield flags patterns for review, not verdicts.

[📊 Full analysis with detailed assessment →](docs/clawhub-security-report.md)

## Example Output

```
🛡️  AgentShield Security Report
📁 Scanned: ./my-skill/ (3 files, 44 lines)

🔴 CRITICAL (3)
  ├─ index.ts:13 — [data-exfil] Reads sensitive data and sends HTTP request
  ├─ index.ts:20 — [backdoor] eval() with dynamic input
  └─ backdoor.sh:6 — [backdoor] shell eval with variable

🟡 WARNING (2)
  ├─ index.ts:23 — [privilege] Code uses 'exec' but SKILL.md doesn't declare it
  └─ index.ts:6  — [sensitive-read] Accesses SSH private key

✅ Score: 0/100 (Critical Risk)
⏱  16ms
```

## Usage

```bash
# Scan a directory
npx @elliotllliu/agentshield scan ./path/to/skill/

# AI-powered deep analysis (uses your own API key)
npx @elliotllliu/agentshield scan ./skill/ --ai --provider openai --model gpt-4o
npx @elliotllliu/agentshield scan ./skill/ --ai --provider anthropic
npx @elliotllliu/agentshield scan ./skill/ --ai --provider ollama --model llama3

# Discover installed agents on your machine
npx @elliotllliu/agentshield discover

# JSON output (for CI/CD pipelines)
npx @elliotllliu/agentshield scan ./skill/ --json

# Fail CI if score drops below threshold
npx @elliotllliu/agentshield scan ./skill/ --fail-under 70

# Disable specific rules
npx @elliotllliu/agentshield scan ./skill/ --disable supply-chain,phone-home

# Only run specific rules
npx @elliotllliu/agentshield scan ./skill/ --enable backdoor,data-exfil

# Generate config files
npx @elliotllliu/agentshield init

# Watch mode — re-scan on file changes
npx @elliotllliu/agentshield watch ./skill/

# Compare two versions
npx @elliotllliu/agentshield compare ./skill-v1/ ./skill-v2/

# Generate a security badge for your README
npx @elliotllliu/agentshield badge ./skill/
```

## CI Integration

### GitHub Action (recommended)

```yaml
# .github/workflows/security.yml
name: Security Scan
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: elliotllliu/agentshield@main
        with:
          path: './skills/'
          fail-under: '70'
```

### npx one-liner

```yaml
- name: Security scan
  run: npx -y @elliotllliu/agentshield scan ./skills/ --fail-under 70
```

### Action Inputs & Outputs

| Input | Default | Description |
|-------|---------|-------------|
| `path` | `.` | Directory to scan |
| `fail-under` | — | Fail if score < threshold (0-100) |
| `format` | `terminal` | `terminal` or `json` |

| Output | Description |
|--------|-------------|
| `score` | Security score (0-100) |
| `findings` | Number of findings |

## Configuration

Create `.agentshield.yml` (or run `agentshield init`):

```yaml
rules:
  disable:
    - supply-chain    # skip npm audit
    - phone-home      # allow periodic HTTP

severity:
  sensitive-read: info   # downgrade to info

failUnder: 70   # CI threshold

ignore:
  - "tests/**"
  - "*.test.ts"
```

### `.agentshieldignore`

```
node_modules/
dist/
*.test.ts
__tests__/
```

## Scoring

| Severity | Points Deducted |
|----------|----------------|
| 🔴 Critical | -25 |
| 🟡 Warning | -10 |
| 🟢 Info | 0 |

| Score | Risk Level | Recommendation |
|-------|------------|----------------|
| 90-100 | ✅ Low Risk | Safe to install |
| 70-89 | 🟡 Moderate | Review warnings |
| 40-69 | 🟠 High Risk | Investigate before using |
| 0-39 | 🔴 Critical | Do not install |

## Supported Platforms

- **AI Agent Skills** — OpenClaw, Codex, Claude Code
- **MCP Servers** — Model Context Protocol tool servers
- **npm Packages** — any npm package with executable code
- **General** — any directory with JS/TS/Python/Shell code

### Supported File Types

| Language | Extensions |
|----------|-----------|
| JavaScript/TypeScript | `.js`, `.ts`, `.mjs`, `.cjs`, `.tsx`, `.jsx` |
| Python | `.py` |
| Shell | `.sh`, `.bash`, `.zsh` |
| Config | `.json`, `.yaml`, `.yml`, `.toml` |
| Docs | `SKILL.md` (permission analysis) |

## Comparison with Other Tools

| Feature | AgentShield | Snyk Agent Scan | npm audit | ESLint Security |
|---------|------------|-----------------|-----------|-----------------|
| AI skill/MCP specific rules | ✅ 20 rules | ✅ 15+ rules | ❌ | ❌ |
| Prompt injection detection | ✅ regex + AI | ✅ LLM (cloud) | ❌ | ❌ |
| Tool poisoning/shadowing | ✅ | ✅ | ❌ | ❌ |
| Agent auto-discovery | ✅ 10 agents | ✅ | ❌ | ❌ |
| AI-powered analysis | ✅ `--ai` (your key) | ✅ (Snyk cloud) | ❌ | ❌ |
| Data exfiltration detection | ✅ | ✅ | ❌ | ❌ |
| Permission mismatch (SKILL.md) | ✅ | ❌ | ❌ | ❌ |
| Zero config / no account | ✅ | ❌ needs Snyk token | ✅ | ❌ |
| 100% offline capable | ✅ | ❌ cloud required | ✅ | ✅ |
| `npx` zero-install | ✅ | ❌ needs Python+uv | ✅ | ❌ |
| GitHub Action | ✅ | ❌ | ❌ | ❌ |
| Web UI | ✅ | ❌ | ❌ | ❌ |
| Choose your own LLM | ✅ OpenAI/Anthropic/Ollama | ❌ Snyk backend | ❌ | ❌ |
| False positive detection | ✅ context-aware | ❌ | ❌ | ❌ |
| No rate limits | ✅ | ❌ daily quota | ✅ | ✅ |
| Open source analysis | ✅ fully open | ❌ black box | ✅ | ✅ |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for how to add new rules.

## Links

- 📦 [npm](https://www.npmjs.com/package/@elliotllliu/agentshield)
- 📖 [Rule Documentation](docs/rules.md)
- 📊 [ClawHub Security Report](docs/clawhub-security-report.md)
- 🇨🇳 [中文 README](README.zh-CN.md)

## License

MIT
