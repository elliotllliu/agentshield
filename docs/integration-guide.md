# Integration Guide: Add AgentShield Security Scanning to Your Platform

> This document explains how to integrate AgentShield security scanning into any skill directory, marketplace, or registry platform. It is written for both humans and AI agents to follow.

## What You Get

Every skill/plugin/MCP server on your platform gets:
- A **security score** (0-100)
- A **risk level** (🟢 Low / 🟡 Moderate / 🟠 High / 🔴 Critical)
- A **list of findings** with file, line, rule, severity, and evidence
- A **scan timestamp** for freshness

## Prerequisites

- Node.js 18+ installed on your server
- Ability to `git clone` repositories
- ~50MB temp disk per scan (cleaned up after)

## Step 1: Install

```bash
npm install -g @elliotllliu/agent-shield
```

Or use npx (no install needed):

```bash
npx -y @elliotllliu/agent-shield scan ./path --json
```

## Step 2: Scan a Skill

### From a GitHub URL

```bash
# Clone the repo (shallow, minimal disk)
git clone --depth 1 https://github.com/owner/repo.git /tmp/scan-target

# Run the scan
agent-shield scan /tmp/scan-target --json > result.json

# Clean up
rm -rf /tmp/scan-target
```

### From a Local Directory

```bash
agent-shield scan ./my-skill --json > result.json
```

## Step 3: Parse the JSON Output

AgentShield outputs a JSON object with this schema:

```json
{
  "target": "/tmp/scan-target",
  "filesScanned": 12,
  "linesScanned": 1847,
  "findings": [
    {
      "rule": "env-leak",
      "severity": "high",
      "file": "src/config.ts",
      "line": 15,
      "message": "Environment variable access with outbound HTTP",
      "evidence": "const key = process.env.API_KEY",
      "confidence": "high",
      "possibleFalsePositive": false
    },
    {
      "rule": "sensitive-read",
      "severity": "low",
      "file": "README.md",
      "line": 42,
      "message": "Accesses SSH private key",
      "evidence": "example: fs.readFileSync('~/.ssh/id_rsa')",
      "possibleFalsePositive": true,
      "falsePositiveReason": "Documentation file — code examples commonly trigger patterns",
      "confidence": "low"
    }
  ],
  "score": 85,
  "riskLevel": "moderate",
  "scanTimeMs": 234
}
```

### Field Reference

| Field | Type | Description |
|-------|------|-------------|
| `target` | string | Path that was scanned |
| `filesScanned` | number | Total files analyzed |
| `linesScanned` | number | Total lines analyzed |
| `score` | number | 0-100 security score |
| `riskLevel` | string | `"low"` / `"moderate"` / `"high"` / `"critical"` |
| `scanTimeMs` | number | Scan duration in milliseconds |
| `findings` | array | List of security findings (see below) |

### Finding Object

| Field | Type | Description |
|-------|------|-------------|
| `rule` | string | Rule ID (e.g., `"backdoor"`, `"data-exfil"`, `"prompt-injection"`) |
| `severity` | string | `"high"` / `"medium"` / `"low"` |
| `file` | string | File path relative to scan target |
| `line` | number | Line number (may be absent for project-level findings) |
| `message` | string | Human-readable description |
| `evidence` | string | Code snippet or pattern that triggered the rule |
| `confidence` | string | `"high"` / `"medium"` / `"low"` |
| `possibleFalsePositive` | boolean | Whether the scanner suspects this is a false positive |
| `falsePositiveReason` | string | Explanation of why it might be a false positive |

### Score Tiers

| Score | Risk Level | Recommended Action |
|-------|-----------|-------------------|
| 90-100 | 🟢 `low` | Safe to install |
| 70-89 | 🟡 `moderate` | Review warnings before using |
| 40-69 | 🟠 `high` | Investigate findings before using |
| 0-39 | 🔴 `critical` | Do not install without thorough review |

### All Rule IDs

**Code Security:**
`data-exfil`, `backdoor`, `reverse-shell`, `crypto-mining`, `credential-hardcode`, `obfuscation`

**Agent-Specific:**
`prompt-injection`, `tool-shadowing`, `env-leak`, `network-ssrf`, `phone-home`, `toxic-flow`, `skill-risks`, `python-security`

**Supply Chain & Config:**
`privilege`, `supply-chain`, `sensitive-read`, `excessive-perms`, `mcp-manifest`, `typosquatting`, `hidden-files`

**Advanced Analysis:**
`cross-file`, `attack-chain`, `multilang-injection`, `python-ast`, `description-integrity`, `mcp-runtime`

## Step 4: Display on Your Platform

### Skill Card (Minimal)

Show on every skill listing card:

```
🛡️ 92/100 🟢 Safe
```

### Skill Detail Page (Full)

Show on the skill detail page:

```
Security Report
━━━━━━━━━━━━━━━
Score:       92/100
Risk Level:  🟢 Low Risk
Scanned:     2026-03-13
Files:       12 files, 1,847 lines

Findings (1):
  🟡 MEDIUM  env-leak
     src/config.ts:15
     Environment variable access with outbound HTTP

Passed Rules (29/30):
  ✅ backdoor  ✅ data-exfil  ✅ reverse-shell
  ✅ prompt-injection  ✅ tool-shadowing  ...

Powered by AgentShield
github.com/elliotllliu/agent-shield
```

### Search & Filter

Add these filter options to your search:
- Filter by risk level: `?risk=low` / `?risk=moderate` / `?risk=high`
- Sort by score: `?sort=security_score`
- Minimum score: `?min_score=70`

## Step 5: Schedule Regular Scans

### Batch Scan Script

```bash
#!/bin/bash
# batch-scan.sh — Scan all skills in a list

SKILLS_FILE="skills.txt"  # One GitHub URL per line
RESULTS_DIR="./scan-results"
mkdir -p "$RESULTS_DIR"

while IFS= read -r repo_url; do
  slug=$(echo "$repo_url" | sed 's|.*/||')
  echo "Scanning $slug..."

  # Clone
  git clone --depth 1 "$repo_url" "/tmp/$slug" 2>/dev/null

  # Scan
  npx -y @elliotllliu/agent-shield scan "/tmp/$slug" --json > "$RESULTS_DIR/$slug.json" 2>/dev/null

  # Clean up
  rm -rf "/tmp/$slug"

  # Rate limit: avoid hammering GitHub
  sleep 2
done < "$SKILLS_FILE"

echo "Done. Results in $RESULTS_DIR/"
```

### Scheduling

| Event | Action |
|-------|--------|
| New skill indexed | Trigger scan immediately |
| Weekly cron | Re-scan all skills to catch repo changes |
| User request | "Re-scan" button triggers on-demand scan |

### Performance Estimates

| Scale | Time (sequential) | Time (4 parallel) |
|-------|-------------------|-------------------|
| 100 skills | ~20 seconds | ~5 seconds |
| 1,000 skills | ~3 minutes | ~1 minute |
| 10,000 skills | ~33 minutes | ~8 minutes |
| 19,000 skills | ~63 minutes | ~16 minutes |

## Step 6: Attribution

Please include on scanned pages:

```
🛡️ Security scan powered by AgentShield
   https://github.com/elliotllliu/agent-shield
```

## Programmatic Usage (Node.js)

If your backend is Node.js, you can call AgentShield programmatically:

```javascript
const { execSync } = require('child_process');

function scanSkill(repoPath) {
  try {
    const output = execSync(
      `npx -y @elliotllliu/agent-shield scan "${repoPath}" --json`,
      { encoding: 'utf-8', timeout: 30000 }
    );
    return JSON.parse(output);
  } catch (error) {
    return { score: null, riskLevel: 'error', error: error.message };
  }
}

// Usage
const result = scanSkill('/tmp/my-cloned-repo');
console.log(`Score: ${result.score}, Risk: ${result.riskLevel}`);
console.log(`Findings: ${result.findings.length}`);
```

## Python Usage

```python
import subprocess
import json

def scan_skill(repo_path):
    try:
        result = subprocess.run(
            ['npx', '-y', '@elliotllliu/agent-shield', 'scan', repo_path, '--json'],
            capture_output=True, text=True, timeout=30
        )
        return json.loads(result.stdout)
    except Exception as e:
        return {'score': None, 'riskLevel': 'error', 'error': str(e)}

# Usage
result = scan_skill('/tmp/my-cloned-repo')
print(f"Score: {result['score']}, Risk: {result['riskLevel']}")
```

## FAQ

**Q: Does AgentShield send data to any server?**
A: No. All scanning is 100% offline. No telemetry, no API calls, no data leaves your machine.

**Q: What languages does it scan?**
A: JavaScript, TypeScript, Python, YAML, JSON, Markdown, and shell scripts.

**Q: What about false positives?**
A: Findings with `possibleFalsePositive: true` are likely false positives (e.g., code examples in documentation). Filter these out for your score display if desired.

**Q: Can I disable specific rules?**
A: Yes: `agent-shield scan ./path --json --disable supply-chain,phone-home`

**Q: What about .difypkg files (Dify plugins)?**
A: Supported. AgentShield auto-extracts and scans them: `agent-shield scan ./plugin.difypkg --json`

---

**AgentShield** — Open source, MIT licensed
GitHub: https://github.com/elliotllliu/agent-shield
npm: https://www.npmjs.com/package/@elliotllliu/agent-shield
