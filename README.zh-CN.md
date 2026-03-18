# 🛡️ AgentShield

**给你的 AI 做个体检。**

一次扫描，十三大引擎，一份报告。

[English](./README.md)

你从网上下了一个 MCP Server / Skill / Plugin，准备装上用。但你心里可能有个疑问：

> 这东西安全吗？会不会偷我的密钥？会不会劫持我的 AI？

**AgentShield 帮你几秒搞定。** 一行命令，13 个独立扫描引擎，一份清晰的报告。

```bash
npx @elliotllliu/agent-shield scan ./那个你想装的东西
```

就这么简单。首次运行会自动帮你装好所有引擎，之后秒出结果。

---

## 看看效果

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

**一眼看出：7 个外部引擎全说没问题。所有严重威胁全部排除。放心装。**

---

## 凭什么信？

因为不是一个引擎说了算。是 **8 个独立的扫描引擎**，每个都是自己领域的专家。我们把它们聚合在一起：

| 引擎 | 它最擅长什么 |
|------|-----------|
| 📋 **AgentShield** *（内置参考）* | AI Agent 基础检查 — Skill 劫持、Prompt 注入、MCP 运行时 |
| 🔍 **[Aguara](https://github.com/garagon/aguara)** | 通用代码安全 — 177 条规则，数据外渗、污点追踪 |
| 🔎 **[Semgrep](https://github.com/semgrep/semgrep)** | 代码质量 — 2000+ 条规则，注入、XSS、硬编码凭证 |
| 🧪 **[Invariant](https://github.com/invariantlabs-ai/mcp-scan)** | MCP 专项 — Tool Poisoning、跨域提权、Rug Pull |
| 🔬 **[Trivy](https://github.com/aquasecurity/trivy)** | 漏洞扫描 + 密钥检测 + SBOM |
| 🔑 **[Gitleaks](https://github.com/gitleaks/gitleaks)** | 密钥和 Token 泄露检测 |
| 🐍 **[Bandit](https://github.com/PyCQA/bandit)** | Python 代码安全 |
| 📡 **[Bearer](https://github.com/Bearer/bearer)** | 数据流 + 隐私分析 |
| 🐕 **[TruffleHog](https://github.com/trufflesecurity/trufflehog)** | 密钥检测 + 验证密钥有效性 |
| 🌐 **[OSV-Scanner](https://github.com/google/osv-scanner)** | 依赖漏洞（Google OSV 数据库） |
| 🦑 **[Grype](https://github.com/anchore/grype)** | 依赖项漏洞扫描 |
| 🟢 **[njsscan](https://github.com/ajinabraham/njsscan)** | Node.js / JavaScript 专项安全 |
| 🔐 **[detect-secrets](https://github.com/Yelp/detect-secrets)** | 密钥检测（Yelp 出品） |

**每家都有自己的长处。我们把众家的长处结合起来，出一个报表。**

内置引擎仅供参考 — 综合结论由 7 个外部引擎的共识决定。它们越强，我们就越强。

---

## 首次运行

首次运行会自动帮你安装所有引擎（装到 `~/.agentshield/`，不需要 sudo）：

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

**装一次，后面就秒跑。**

---

## 都能扫出什么？

| 风险 | 啥意思 |
|------|------|
| 🔴 插件劫持 | 它在偷偷改你 AI 的设置 |
| 🔴 后门 | 它能悄悄执行任意代码 |
| 🔴 远程控制 | 它在连外面的服务器 + 开 shell |
| ⚠️ 偷数据 | 它读了你的密钥/文件然后发出去了 |
| ⚠️ Prompt 注入 | 它在偷偷给你的 AI 加指令 |
| ⚠️ Tool Poisoning | 工具描述里藏了恶意指令 |
| ⚠️ 代码混淆 | 代码故意搞得看不懂，可能在藏什么 |
| ⚠️ 已知漏洞 | 依赖项有已知的 CVE |
| ⚠️ 密钥泄露 | 代码里有 API key、token、密码 |
| ℹ️ 权限过大 | 它要的权限比它需要的多 |

---

## 其他玩法

```bash
# HTML 报告，发给同事看
agent-shield scan ./dir --html -o report.html

# JSON，接到 CI/CD 里
agent-shield scan ./dir --json

# 英文报告
agent-shield scan ./dir --lang en

# SARIF，GitHub Code Scanning
agent-shield scan ./dir --sarif -o results.sarif
```

---

## 安装

```bash
# 推荐：用 npx，不用装
npx @elliotllliu/agent-shield scan ./my-skill/

# 或者全局装
npm install -g @elliotllliu/agent-shield
```

---

## 我们怎么想的

> **"我们不竞争 — 我们聚合。"**

我们把每一家引擎的长处聚合在一起，交叉验证它们的发现，最终出一个统一的报表。每家引擎越强，AgentShield 就越强。

**我们是 X 光机，不是医生。** 我们照出里面有什么 — 你来决定要不要装。

---

## License

MIT
