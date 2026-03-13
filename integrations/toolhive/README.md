# AgentShield × ToolHive Integration (PoC)

Pre-install security scanning for ToolHive MCP servers.

## What it does

Wraps `thv run` to automatically scan MCP server source code with AgentShield before deployment.

```
thv-safe run fetch        # scans → shows report → asks to proceed
thv-safe run fetch --yes  # scans → auto-proceed if grade ≥ C
thv-safe scan fetch       # scan only, don't run
```

## How it works

1. Resolves the server name via ToolHive's registry (`thv registry list`)
2. Finds the source repository from registry metadata
3. Clones the repo (shallow) and runs `agent-shield scan`
4. Shows the security report with grade (A–F)
5. If grade ≥ C: proceeds with `thv run`
6. If grade D/F: warns and asks for confirmation

## Install

```bash
npm install -g @elliotllliu/agent-shield
# Copy thv-safe to your PATH
cp thv-safe /usr/local/bin/
chmod +x /usr/local/bin/thv-safe
```

## Requirements

- [ToolHive](https://github.com/stacklok/toolhive) installed (`thv` CLI)
- [AgentShield](https://github.com/elliotllliu/agent-shield) installed (`agent-shield` CLI)
- `git` for cloning source repos

## Example Output

```
$ thv-safe run fetch

🛡️  AgentShield Pre-Install Scan
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📦 Server: fetch
🔗 Source: https://github.com/user/mcp-fetch
📄 Files:  12 files, 1.2K lines
⏱  Time:   340ms

Score: 87/100  █████████████████░░░  (B · Good)

✅ No high-risk findings.
🟡 2 medium-risk findings (review recommended)

Proceed with `thv run fetch`? [Y/n]
```
