# AgentShield Phase 4 — 开发 Checklist

**目标：** 检测能力超越 snyk/agent-scan
**总预估：** ~8 小时

---

## 4.1 Prompt Injection 检测（regex 基础版）⭐

~~`prompt-injection.ts` 已写好，需收尾注册。~~

- [x] 4.1.1 `src/rules/index.ts` 里 import + 注册 `promptInjection`
- [x] 4.1.2 写 `tests/prompt-injection.test.ts` — 47 个测试
- [x] 4.1.3 `npm run build` 编译通过
- [x] 4.1.4 `npm test` 全部通过
- [x] 4.1.5 `fixtures/malicious-skill/` 端到端验证
- [x] 4.1.6 **升级**: 55+ regex 模式，8 大分类（基于论文调研）
- [x] 4.1.7 **升级**: 多语言注入 (中/西/法/德)
- [x] 4.1.8 **升级**: TPA <IMPORTANT> 标签检测
- [x] 4.1.9 **升级**: Python MCP docstring 检测
- [x] 4.1.10 **升级**: advanced-attacks fixture + 25 个新测试

**难度：** ⭐ 简单
**依赖：** 无
**CLI 影响：** 无（规则自动注册）
**预估：** 30 分钟

---

## 4.2 LLM Prompt Injection（`--llm` flag）⭐⭐⭐

~~可选 LLM 深度分析，用户传自己的 API key。~~

- [x] 4.2.1 `src/llm/types.ts` — LlmProvider 接口 + LlmFinding 类型
- [x] 4.2.2 `src/llm/openai.ts` — OpenAI provider (fetch)
- [x] 4.2.3 `src/llm/anthropic.ts` — Anthropic provider (fetch)
- [x] 4.2.4 `src/llm/ollama.ts` — Ollama provider (localhost:11434)
- [x] 4.2.5 `src/llm/index.ts` — createProvider() 工厂 + system prompt
- [x] 4.2.6 `src/scanner/index.ts` — scanWithLlm() async 版本
- [x] 4.2.7 `src/cli.ts` — --ai / --provider / --model 选项
- [x] 4.2.8 regex + LLM 结果合并去重
- [x] 4.2.9 `src/llm-analyzer.ts` — 独立 LLM 分析模块
- [ ] 4.2.10 README 加使用说明 + 示例

**难度：** ⭐⭐⭐ 中高
**依赖：** 4.1 完成（prompt-injection 规则注册后才能做去重）
**CLI 影响：** 新增 3 个 flag
**API 影响：** scan() 变 async（breaking，需 bump minor version）
**预估：** 3-4 小时

### 关键决策
- **不引入 SDK 依赖**：用原生 fetch 调 API，保持零依赖（除了已有的 chalk/commander/glob）
- **LLM 不扫代码**：只扫 SKILL.md、README.md、*.json、*.yaml — 节省 token，代码有 regex 覆盖
- **降级策略**：LLM 调用失败时 fallback 到 regex，不中断扫描

---

## 4.3 Tool Shadowing 检测 ⭐⭐

~~跨 MCP server 配置比对工具名冲突（对标 snyk E002）。~~

- [x] 4.3.1 `src/rules/tool-shadowing.ts` — 跨 config 工具名比对 + 覆盖意图检测
- [x] 4.3.2 注册规则到 index.ts
- [x] 4.3.3 写测试 `tests/tool-shadowing.test.ts` — 11 个测试
- [ ] 4.3.4 CLI 加 `--mcp-config` 多路径输入（standalone 模式）

**难度：** ⭐⭐ 中等
**依赖：** 独立，可与 4.1 并行
**CLI 影响：** 新增 `--mcp-config` flag
**预估：** 2 小时

---

## 4.4 Agent 配置自动发现 ⭐

~~自动扫描本机已安装 AI agent 的 MCP 配置文件。~~

- [x] 4.4.1 `src/discover.ts` — 10 种 agent 路径 + MCP server 计数
- [x] 4.4.2 CLI `agentshield discover` 命令
- [x] 4.4.3 `--json` 输出
- [x] 4.4.4 `--scan` 自动扫描所有发现的配置
- [x] 4.4.5 写测试 `tests/discover.test.ts` — 3 个测试

**难度：** ⭐ 简单（硬编码路径）
**依赖：** 独立；4.4.4 依赖 4.3
**CLI 影响：** 新增 `discover` 命令
**预估：** 1.5 小时

---

## 执行顺序

```
4.1 (30min) ──→ 4.2 (3-4h)
4.3 (2h)    ↗ 可并行
4.4 (1.5h)  ↗ 可并行，4.4.4 依赖 4.3
```

**推荐：** 4.1 → 4.3 + 4.4 并行 → 4.2

## 完成后 vs snyk/agent-scan 对比

| 能力 | snyk | AgentShield |
|------|------|-------------|
| Prompt Injection (regex) | ❌ 无 | ✅ 25+ 模式 |
| Prompt Injection (LLM) | ✅ 黑盒 | ✅ 用户选模型 |
| Tool Shadowing | ✅ | ✅ |
| 配置自动发现 | ✅ | ✅ |
| 静态代码规则 | 6 条 | 18 条 |
| 需要注册/token | ✅ 必须 | ❌ 不需要 |
| Daily quota | ✅ 有 | ❌ 无限制 |
| GitHub Action | ❌ | ✅ |
| Web 在线版 | ❌ | ✅ |
| 选择 LLM 模型 | ❌ | ✅ |
