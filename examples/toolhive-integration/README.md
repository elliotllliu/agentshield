# ToolHive × AgentShield Integration

Proof-of-concept: Scan all MCP servers in a ToolHive registry for security vulnerabilities.

## Quick Start

```bash
# Download registry
curl -sL https://raw.githubusercontent.com/stacklok/toolhive-registry-server/main/examples/toolhive-registry.json > registry.json

# Run scan
node toolhive-agentshield-integration.mjs registry.json

# With CI threshold
node toolhive-agentshield-integration.mjs registry.json --fail-under 60
```

## What It Does

1. Reads a ToolHive `registry.json`
2. Clones each server's source repository
3. Runs AgentShield scan on each
4. Outputs scores, grades, and findings
5. Generates `registry-enrichment.json` for metadata integration

## CI Integration

See [GITHUB-ACTIONS.md](./GITHUB-ACTIONS.md) for a ready-to-use GitHub Actions workflow.

## Results (2026-03-13)

| Server | Score | Grade |
|--------|-------|-------|
| fetch | 97 | ✅ A |
| filesystem | 94.6 | ✅ A |
| arxiv | 88 | 🟡 B |
| github | 81.1 | 🟡 B |
| browserbase | 65.5 | 🟠 C |
| chrome-devtools | 54.5 | 🔴 D |
| apollo | 47.1 | 🔴 D |
| crowdstrike | 36.1 | ⛔ F |
| adb-mysql | 21.1 | ⛔ F |
