# 🛡️ AgentShield

**Give your AI a health check.**

One scan. Four engines. One report.

[中文文档](./README.zh-CN.md)

You found an MCP Server / Skill / Plugin online and want to install it. But you're wondering:

> Is this thing safe? Will it steal my API keys? Hijack my AI? Mine crypto?

**AgentShield answers that in 3 seconds.** One command, 4 independent scanning engines, one clear report.

```bash
npx @elliotllliu/agent-shield scan ./that-thing-you-want-to-install
```

That's it. First run auto-installs all engines. After that, results come in seconds.

---

## See It In Action

### When risks are found

```
🛡️  Security Report
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📁 Target:   ./mcp-playwright
🔧 Engines:  4 independent scanners
⏱  Time:     12.3s

──────────────────────────────────────────────────────
🔍 Individual Conclusions
──────────────────────────────────────────────────────

🛡️ AgentShield — AI Agent Security
   Verdict: ⚠️ 2 items need attention
   • Code obfuscation
     📍 src/index.ts:1

🔍 Aguara — General Code Security
   Verdict: ✅ No risks found

🔎 Semgrep — Code Quality & Injection
   Verdict: ✅ No risks found

🧪 Invariant — MCP Tool Poisoning
   Verdict: ✅ No risks found

──────────────────────────────────────────────────────
📊 Overall Assessment
──────────────────────────────────────────────────────

✅ Safe overall, minor notes
   3/4 engines found no issues

  ✅ Backdoors        — All 4 engines clear
  ✅ Data theft        — All 4 engines clear
  ✅ Prompt injection  — All 4 engines clear
  ✅ Crypto mining     — All 4 engines clear

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

**One glance: 3 out of 4 engines say it's clean. All major threats cleared. Safe to install.**

### When everything is clean

```
✅ All engines found no risks

  ✅ Backdoors        — All 4 engines clear
  ✅ Data theft        — All 4 engines clear
  ✅ Prompt injection  — All 4 engines clear
  ✅ Crypto mining     — All 4 engines clear
```

**All green. Go ahead and install.**

---

## Why Trust It?

Because it's not one engine making the call. It's **4 independent scanning engines**, each a specialist in their own domain. We don't compete with them — we bring them together.

| Engine | What it's best at |
|--------|------------------|
| 🛡️ **AgentShield** | AI Agent threats — skill hijack, prompt injection, MCP runtime |
| 🔍 **[Aguara](https://github.com/garagon/aguara)** | General security — 177 rules, data exfil, taint tracking |
| 🔎 **[Semgrep](https://github.com/semgrep/semgrep)** | Code quality — 2000+ rules, injection, XSS, hardcoded secrets |
| 🧪 **[Invariant](https://github.com/invariantlabs-ai/mcp-scan)** | MCP-specific — tool poisoning, cross-origin escalation, rug pull |

**Each engine has its own strengths. We combine all of them into one report.**

The stronger they get, the stronger we get. We're not building another scanner — we're building the layer that makes every scanner better by cross-validating their results.

**If 3 engines say safe and 1 says dangerous → probably a false positive.**
**If 3 engines say dangerous → it's real.**

---

## First Run

First time you run it, engines are auto-installed (to `~/.agentshield/`, no sudo needed):

```
🔧 Checking engines...
  ✅ AgentShield — Ready
  📦 Aguara — Installing... Done
  📦 Semgrep — Installing... Done
  📦 Invariant — Installing... Done
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

Snyk has great agent scanning. Cisco has skill-scanner. Semgrep has 2000+ rules. Invariant catches tool poisoning. Each one is excellent at what they do.

We bring them all together. We combine every engine's strengths, cross-validate their findings, and produce one unified report. The stronger each engine gets, the stronger AgentShield gets.

**We're the X-ray machine, not the doctor.** We show you what's inside — you decide whether to install it. But we make that decision easy by giving you every expert's opinion in one place.

---

## License

MIT
