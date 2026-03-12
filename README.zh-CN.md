# 🛡️ AgentShield — AI Agent 安全扫描器

[![npm](https://img.shields.io/npm/v/@elliotllliu/agentshield)](https://www.npmjs.com/package/@elliotllliu/agentshield)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

专为 AI Agent 技能、MCP Server、插件设计的安全扫描工具。在安装第三方扩展之前，检测数据窃取、后门、凭证泄露和供应链漏洞。

> **我们扫描了 ClawHub 热门 skill 仓库 — 平均安全分仅 47/100。** [查看完整报告 →](docs/clawhub-security-report.md)

## 为什么需要 AgentShield？

AI Agent 会安装并执行第三方技能和插件，安全审查几乎为零。一个恶意 skill 就能：

- 🔑 **偷凭证** — SSH 密钥、AWS Secret、API Token
- 📤 **外泄数据** — 读取敏感文件发送到外部服务器
- 💀 **植入后门** — eval()、反弹 Shell、动态代码执行
- ⛏️ **挖矿** — 利用你的算力挖加密货币
- 🕵️ **越权** — 声称只读但实际执行 Shell 命令

AgentShield 用 **16 条安全规则**在 50ms 内检出这些威胁。

## 快速开始

```bash
npx @elliotllliu/agentshield scan ./my-skill/
```

无需安装，Node.js 18+ 即可运行。

## 16 条安全规则

### 🔴 严重（自动判定不安全）

| 规则 | 检测内容 |
|------|----------|
| `data-exfil` | 读敏感文件 + 发 HTTP 请求（数据外泄模式） |
| `backdoor` | `eval()`、`exec()`、动态代码执行 |
| `reverse-shell` | Socket 外连 + Shell 管道 |
| `crypto-mining` | 矿池连接、xmrig、coinhive |
| `credential-hardcode` | 硬编码 AWS Key、GitHub PAT、Stripe Key |
| `env-leak` | 环境变量 + HTTP 外发 |
| `obfuscation` | base64+eval、十六进制混淆 |
| `typosquatting` | npm 包名仿冒（`1odash` → `lodash`） |
| `hidden-files` | `.env` 明文密钥 |

### 🟡 警告（建议审查）

| 规则 | 检测内容 |
|------|----------|
| `network-ssrf` | 用户可控 URL、SSRF |
| `privilege` | SKILL.md 声明 vs 代码实际行为不匹配 |
| `supply-chain` | npm 依赖已知 CVE |
| `sensitive-read` | 读取 SSH 密钥、AWS 凭证 |
| `excessive-perms` | 权限声明过多 |
| `phone-home` | 定时器 + HTTP 心跳 |
| `mcp-manifest` | MCP Server 通配权限、可疑工具描述 |

## 真实扫描数据

我们扫了 ClawHub **Top 9 热门 skill 仓库**（总安装量 70 万+）：

| 仓库 | 安装量 | 分数 | 风险 |
|------|--------|------|------|
| vercel-labs/agent-skills | 157K | 🔴 0/100 | deploy 脚本有 `$(curl)` 命令替换 |
| obra/superpowers | 94K | 🔴 0/100 | 渲染脚本有动态代码执行 |
| coreyhaines31/marketingskills | 42K | 🔴 0/100 | 122 个 critical（CRM 凭证模式） |
| anthropics/skills | 36K | 🔴 35/100 | 模板有 exec() |
| google-labs-code/stitch-skills | 63K | ✅ 100/100 | 干净 |
| supercent-io/skills-template | 106K | ✅ 100/100 | 干净 |

**平均分：47/100** — 超半数热门 skill 有严重安全隐患。

## 使用方法

```bash
# 扫描目录
npx @elliotllliu/agentshield scan ./skill/

# JSON 输出
npx @elliotllliu/agentshield scan ./skill/ --json

# CI 门禁
npx @elliotllliu/agentshield scan ./skill/ --fail-under 70

# 禁用特定规则
npx @elliotllliu/agentshield scan ./skill/ --disable supply-chain

# 初始化配置
npx @elliotllliu/agentshield init

# 实时监控
npx @elliotllliu/agentshield watch ./skill/

# 版本对比
npx @elliotllliu/agentshield compare ./v1/ ./v2/

# 生成安全徽章
npx @elliotllliu/agentshield badge ./skill/
```

## GitHub Actions 集成

```yaml
- uses: elliotllliu/agentshield@main
  with:
    path: './skills/'
    fail-under: '70'
```

## 与其他工具对比

| 功能 | AgentShield | npm audit | Snyk | ESLint |
|------|------------|-----------|------|--------|
| AI Skill/MCP 专用规则 | ✅ | ❌ | ❌ | ❌ |
| 数据外泄检测 | ✅ | ❌ | ❌ | ❌ |
| 权限不匹配检测 | ✅ | ❌ | ❌ | ❌ |
| 零配置 | ✅ | ✅ | ❌ | ❌ |
| < 50ms 扫描 | ✅ | ❌ | ❌ | ❌ |

## 链接

- 📦 [npm](https://www.npmjs.com/package/@elliotllliu/agentshield)
- 📖 [规则文档](docs/rules.md)
- 📊 [ClawHub 安全报告](docs/clawhub-security-report.md)
- 🇬🇧 [English README](README.md)

## 许可证

MIT
