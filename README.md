# 🛡️ AgentShield

**Give your AI a health check.**

One scan. Thirteen engines. One report.

[中文文档](./README.zh-CN.md)

You found an MCP Server / Skill / Plugin online and want to install it. But you're wondering:

> Is this thing safe? Will it steal my API keys? Hijack my AI? Mine crypto?

**AgentShield answers that in seconds.** One command, 13 independent scanning engines, one clear report.

```bash
npx @elliotllliu/agent-shield scan ./that-thing-you-want-to-install
```

That's it. First run auto-installs all engines. After that, results come in seconds.

---

## See It In Action

```
🛡️  安全检测报告
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📁 检测对象:  ./mcp-puppeteer
🔧 检测引擎:  13 个独立扫描器
⏱  总耗时:    50.2s

──────────────────────────────────────────────────────
🔍 各方检测结论
──────────────────────────────────────────────────────

📋 AgentShield — 内置参考（AI Agent 基础检查）
   结论: ⚠️ 发现 1 处需关注
   • 代码混淆  📍 src/index.ts:1

🔍 Aguara — 通用代码安全
   结论: ✅ 未发现风险

🔎 Semgrep — 代码质量与注入检测
   结论: ✅ 未发现风险

🧪 Invariant — MCP Tool Poisoning 检测
   结论: ✅ 未发现风险

🔬 Trivy — 漏洞扫描 + 密钥检测
   结论: ✅ 未发现风险

🔑 Gitleaks — 密钥和 Token 泄露
   结论: ✅ 未发现风险

🐍 Bandit — Python 代码安全
   结论: ✅ 未发现风险

📡 Bearer — 数据流 + 隐私分析
   结论: ✅ 未发现风险

──────────────────────────────────────────────────────
📊 综合结论
──────────────────────────────────────────────────────

✅ 所有引擎均未检出风险
   （7/7 个外部引擎未检出风险）

  ✅ 后门/远程控制  — 7 个引擎均未检出
  ✅ 数据窃取       — 7 个引擎均未检出
  ✅ Prompt 注入    — 7 个引擎均未检出
  ✅ 挖矿行为       — 7 个引擎均未检出

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

**One glance: 7 out of 7 external engines say it's clean. All major threats cleared. Safe to install.**

---

## Why Trust It?

Because it's not one engine making the call. It's **13 independent scanning engines**, each a specialist in their own domain. We bring them together:

| Engine | What it's best at |
|--------|------------------|
| 📋 **AgentShield** *(reference)* | AI Agent basics — skill hijack, prompt injection, MCP runtime |
| 🔍 **[Aguara](https://github.com/garagon/aguara)** | General security — 177 rules, data exfil, taint tracking |
| 🔎 **[Semgrep](https://github.com/semgrep/semgrep)** | Code quality — 2000+ rules, injection, XSS, hardcoded secrets |
| 🧪 **[Invariant](https://github.com/invariantlabs-ai/mcp-scan)** | MCP-specific — tool poisoning, cross-origin escalation, rug pull |
| 🔬 **[Trivy](https://github.com/aquasecurity/trivy)** | Vulnerability scan + secret detection + SBOM |
| 🔑 **[Gitleaks](https://github.com/gitleaks/gitleaks)** | Secret and token leak detection |
| 🐍 **[Bandit](https://github.com/PyCQA/bandit)** | Python code security |
| 📡 **[Bearer](https://github.com/Bearer/bearer)** | Data flow + privacy analysis |
| 🐕 **[TruffleHog](https://github.com/trufflesecurity/trufflehog)** | Secret detection + verification if active |
| 🌐 **[OSV-Scanner](https://github.com/google/osv-scanner)** | Dependency vulnerabilities (Google OSV database) |
| 🦑 **[Grype](https://github.com/anchore/grype)** | Dependency vulnerability scanning |
| 🟢 **[njsscan](https://github.com/ajinabraham/njsscan)** | Node.js / JavaScript security |
| 🔐 **[detect-secrets](https://github.com/Yelp/detect-secrets)** | Secret detection (Yelp) |

**Each engine has its own strengths. We combine all of them into one report.**

The built-in engine is reference-only — the overall conclusion is decided by the 7 external engines' consensus. The stronger they get, the stronger we get.

---

## First Run

First time you run it, engines are auto-installed (to `~/.agentshield/`, no sudo needed):

```
🔧 检查引擎...
  ✅ AgentShield — 已就绪
  📦 Aguara — 正在安装... 完成
  📦 Semgrep — 正在安装... 完成
  📦 Invariant — 正在安装... 完成
  📦 Trivy — 正在安装... 完成
  📦 Gitleaks — 正在安装... 完成
  📦 Bandit — 正在安装... 完成
  📦 Bearer — 正在安装... 完成
```

**One-time setup. After that, it's instant.**

---

## What Can It Detect?

| Risk | What it means |
|------|--------------|
| 🔴 Skill Hijack | It's secretly modifying your AI's config |
| 🔴 Backdoor | It can silently execute arbitrary code |
| 🔴 Remote Control | It's connecting to external servers + opening a shell |
| ⚠️ Data Theft | It reads your keys/files and sends them out |
| ⚠️ Prompt Injection | It's secretly adding instructions to your AI |
| ⚠️ Tool Poisoning | Hidden malicious instructions in tool descriptions |
| ⚠️ Obfuscated Code | Code is intentionally unreadable — might be hiding something |
| ⚠️ Vulnerabilities | Known CVEs in dependencies |
| ⚠️ Secret Leaks | API keys, tokens, passwords in source code |
| ℹ️ Excessive Permissions | It asks for more than it needs |

---

## More Options

```bash
# HTML report (shareable)
agent-shield scan ./dir --html -o report.html

# JSON (for CI/CD)
agent-shield scan ./dir --json

# Chinese report (default)
agent-shield scan ./dir --lang zh

# SARIF (GitHub Code Scanning)
agent-shield scan ./dir --sarif -o results.sarif
```

---

## Install

```bash
# Recommended: use npx, nothing to install
npx @elliotllliu/agent-shield scan ./my-skill/

# Or install globally
npm install -g @elliotllliu/agent-shield
```

---

## Our Philosophy

> **"We don't compete — we aggregate."**

We bring every engine's strengths together, cross-validate their findings, and produce one unified report. The stronger each engine gets, the stronger AgentShield gets.

**We're the X-ray machine, not the doctor.** We show you what's inside — you decide whether to install it.

---

## License

MIT
