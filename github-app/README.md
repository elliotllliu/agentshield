# 🛡️ AgentShield GitHub App

Automatically scan every PR for AI agent security vulnerabilities.

## What It Does

When installed on a repository, AgentShield automatically:

1. **Scans every PR** for security issues (backdoors, data exfiltration, prompt injection, etc.)
2. **Posts a comment** with a detailed security report (score, findings table)
3. **Creates a check** that passes/fails based on your configured threshold

## PR Comment Example

> ## 🛡️ AgentShield Security Scan
>
> | Metric | Value |
> |--------|-------|
> | Score | ✅ **95/100** |
> | 🔴 High | 0 |
> | 🟡 Medium | 1 |
> | 🟢 Low | 2 |
>
> ✅ **Passed** (threshold: 70)

## Setup

### 1. Install the App

Click **[Install AgentShield](https://github.com/apps/agent-shield)** on your repository.

### 2. Configure (Optional)

Add `.agent-shield.yml` to your repo root:

```yaml
# Minimum score to pass the check (default: 70)
failUnder: 70

# Rules to disable
disable:
  - supply-chain
  - phone-home

# Paths to scan (default: root)
paths:
  - skills/
  - plugins/
  - mcp-servers/
```

### 3. That's It!

Every PR will now be automatically scanned. The check will fail if the score drops below your threshold.

## Self-Hosting

If you want to run your own instance:

```bash
cd github-app
npm install
npm run build

# Set environment variables
export APP_ID=<your-app-id>
export PRIVATE_KEY=<path-to-pem>
export WEBHOOK_SECRET=<your-secret>

npm start
```

### Deploy to Vercel / Railway / Fly.io

The app is a standard Probot application and can be deployed anywhere Node.js runs.

## How It Works

1. Listens for `pull_request.opened` and `pull_request.synchronize` events
2. Clones the PR branch (shallow clone for speed)
3. Runs `@elliotllliu/agent-shield` scan with 31 security rules
4. Posts results as PR comment + GitHub Check

## Security Rules

The app uses all 31 AgentShield rules including:
- 🔴 Backdoors, data exfiltration, reverse shells, crypto mining
- 🟡 Prompt injection (8 languages), tool shadowing, SSRF
- 🟢 Supply chain, permission mismatches, hidden files
- 🆕 Python AST taint tracking, cross-file correlation, attack chain detection

See [full rule list](https://github.com/elliotllliu/agent-shield#what-it-detects--30-security-rules).

## License

MIT
