# 🛡️ AgentShield

**Security scanner for AI agent skills, MCP servers, and plugins.**

[![npm](https://img.shields.io/npm/v/@elliotllliu/agentshield)](https://www.npmjs.com/package/@elliotllliu/agentshield)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

Catch data exfiltration, backdoors, privilege escalation, credential leaks, and supply chain vulnerabilities **before** they reach your AI agents.

> **We scanned the top ClawHub skill repos to understand the security surface area.** Many findings are false positives from legitimate code (API integrations, deploy scripts), but they highlight patterns that malicious skills could exploit. [Read the full report →](docs/clawhub-security-report.md)

## Why AgentShield?

AI agents install and execute third-party skills, MCP servers, and plugins with minimal security review. A single malicious skill can:

- 🔑 **Steal credentials** — SSH keys, AWS secrets, API tokens
- 📤 **Exfiltrate data** — read sensitive files and send them to external servers
- 💀 **Open backdoors** — `eval()`, reverse shells, dynamic code execution
- ⛏️ **Mine crypto** — hijack compute for cryptocurrency mining
- 🕵️ **Bypass permissions** — claim "read-only" but execute shell commands

AgentShield catches these patterns with **16 security rules** in under 50ms.

## Quick Start

```bash
npx @elliotllliu/agentshield scan ./my-skill/
```

No installation required. Works with Node.js 18+.

## What It Detects — 16 Security Rules

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

## Real-World Scan Data

We scanned the **top 9 ClawHub skill repositories** (700K+ combined installs). Most findings are **false positives from legitimate code** (deploy scripts, API integrations), but they demonstrate patterns that malicious skills could replicate:

| Repository | Installs | Raw Score | Assessment |
|------------|----------|-----------|------------|
| vercel-labs/agent-skills | 157K | 0 | ✅ False positives — deploy scripts use `curl` legitimately |
| obra/superpowers | 94K | 0 | ⚠️ Test code + render exec() |
| coreyhaines31/marketingskills | 42K | 0 | ⚠️ 100+ API wrapper tools (legitimate credential access) |
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

| Feature | AgentShield | npm audit | Snyk | ESLint Security |
|---------|------------|-----------|------|-----------------|
| AI skill/MCP specific rules | ✅ | ❌ | ❌ | ❌ |
| Data exfiltration detection | ✅ | ❌ | ❌ | ❌ |
| Permission mismatch (SKILL.md) | ✅ | ❌ | ❌ | ❌ |
| Credential hardcode detection | ✅ | ❌ | ✅ | ✅ |
| Supply chain CVEs | ✅ | ✅ | ✅ | ❌ |
| Zero config | ✅ | ✅ | ❌ | ❌ |
| No API key required | ✅ | ✅ | ❌ | ✅ |
| < 50ms scan time | ✅ | ❌ | ❌ | ❌ |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for how to add new rules.

## Links

- 📦 [npm](https://www.npmjs.com/package/@elliotllliu/agentshield)
- 📖 [Rule Documentation](docs/rules.md)
- 📊 [ClawHub Security Report](docs/clawhub-security-report.md)
- 🇨🇳 [中文 README](README.zh-CN.md)

## License

MIT
