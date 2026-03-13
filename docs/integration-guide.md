# Integrate AgentShield Into Your Platform

> Add security scanning to your skill directory, MCP marketplace, or plugin registry. Every listing gets a trust score — your users get peace of mind.

---

## Why Integrate

Skill directories list thousands of community-contributed tools. Users install them into AI agents that have access to files, credentials, and APIs. **One malicious skill can steal everything.**

Snyk's 2026 research found **36% of audited agent skills contained security flaws** — 1,467 malicious payloads across a single registry.

By integrating AgentShield, your platform becomes the first directory where users can **verify before they install**.

## What Your Users See

### Skill Card

```
┌──────────────────────────────────────────┐
│  📦 awesome-filesystem-tool      ⭐ 342  │
│  by someauthor                           │
│                                          │
│  File system access for AI agents.       │
│                                          │
│  🛡️ 92/100 🟢 Verified Safe             │
│  Scanned Mar 13, 2026                    │
└──────────────────────────────────────────┘
```

### Security Detail Page

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
     "Environment variable access with outbound HTTP"

Passed Rules (29/30):
  ✅ backdoor  ✅ data-exfil  ✅ reverse-shell
  ✅ prompt-injection  ✅ tool-shadowing  ...

Powered by AgentShield
github.com/elliotllliu/agent-shield
```

### Score Tiers

| Score | Badge | Meaning |
|-------|-------|---------|
| 90-100 | 🟢 Verified Safe | No high-risk findings |
| 70-89 | 🟡 Review Advised | Has warnings, generally safe |
| 40-69 | 🟠 High Risk | Investigate before using |
| 0-39 | 🔴 Critical Risk | Do not install without review |

### Search & Filter

Your users can:
- Filter by risk level: show only 🟢 verified skills
- Sort by security score
- Hide 🔴 critical skills by default

## What You Get

- **Trust differentiation** — no other directory does this
- **Free scanning** — AgentShield is MIT-licensed, runs 100% offline
- **Zero data sharing** — nothing leaves your server
- **Fast** — ~200ms per skill, 19,000 skills in ~16 minutes (4 parallel)

## Attribution

Include on scanned pages:

```
🛡️ Security scan powered by AgentShield
   https://github.com/elliotllliu/agent-shield
```

---

# Technical Integration Guide

> The section below is for developers and AI agents implementing the integration. It contains the exact commands, JSON schema, code examples, and edge cases needed to build this.

## Prerequisites

- Node.js 18+
- Git (for cloning repos)
- ~50MB temp disk per scan (cleaned up after)

## Install

```bash
npm install -g @elliotllliu/agent-shield
```

Or use npx (no global install):

```bash
npx -y @elliotllliu/agent-shield scan ./path --json
```

## Scan a Skill

### Basic Flow

```bash
# 1. Clone the repo (shallow)
git clone --depth 1 https://github.com/owner/repo.git /tmp/scan-target

# 2. Scan and get JSON
agent-shield scan /tmp/scan-target --json > result.json

# 3. Clean up
rm -rf /tmp/scan-target
```

### CLI Options

```bash
agent-shield scan <path> [options]

Options:
  --json                Output JSON (required for integration)
  --fail-under <score>  Exit code 1 if score below threshold
  --disable <rules>     Comma-separated rules to skip
  --enable <rules>      Only run these rules
```

## JSON Output Schema

```json
{
  "target": "/tmp/scan-target",
  "filesScanned": 12,
  "linesScanned": 1847,
  "score": 85,
  "riskLevel": "moderate",
  "scanTimeMs": 234,
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
  ]
}
```

### Top-Level Fields

| Field | Type | Description |
|-------|------|-------------|
| `target` | string | Path that was scanned |
| `filesScanned` | number | Total files analyzed |
| `linesScanned` | number | Total lines analyzed |
| `score` | number (0-100) | Security score. Higher = safer |
| `riskLevel` | string | One of: `"low"`, `"moderate"`, `"high"`, `"critical"` |
| `scanTimeMs` | number | Scan duration in milliseconds |
| `findings` | array | List of finding objects |

### Finding Object Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `rule` | string | yes | Rule ID that triggered |
| `severity` | string | yes | `"high"` / `"medium"` / `"low"` |
| `file` | string | yes | File path relative to scan target |
| `line` | number | no | Line number (absent for project-level findings) |
| `message` | string | yes | Human-readable description |
| `evidence` | string | no | Code snippet or pattern matched |
| `confidence` | string | yes | `"high"` / `"medium"` / `"low"` |
| `possibleFalsePositive` | boolean | no | `true` if scanner suspects false positive |
| `falsePositiveReason` | string | no | Why it might be a false positive |

### Score Calculation

| Severity | Points Deducted |
|----------|----------------|
| 🔴 High | -25 per finding |
| 🟡 Medium | -8 per finding |
| 🟢 Low | -2 per finding |

Findings marked `possibleFalsePositive: true` are excluded from scoring.

### Risk Level Mapping

| Score Range | riskLevel value |
|-------------|----------------|
| 90-100 | `"low"` |
| 70-89 | `"moderate"` |
| 40-69 | `"high"` |
| 0-39 | `"critical"` |

### All 30 Rule IDs

**Code Security (6):**
`data-exfil`, `backdoor`, `reverse-shell`, `crypto-mining`, `credential-hardcode`, `obfuscation`

**Agent-Specific (8):**
`prompt-injection`, `tool-shadowing`, `env-leak`, `network-ssrf`, `phone-home`, `toxic-flow`, `skill-risks`, `python-security`

**Supply Chain & Config (7):**
`privilege`, `supply-chain`, `sensitive-read`, `excessive-perms`, `mcp-manifest`, `typosquatting`, `hidden-files`

**Advanced Analysis (6):**
`cross-file`, `attack-chain`, `multilang-injection`, `python-ast`, `description-integrity`, `mcp-runtime`

**AI Deep Analysis (3, requires --ai flag):**
`ai-backdoor`, `ai-data-exfil`, `ai-prompt-injection`

## Code Examples

### Node.js

```javascript
const { execSync } = require('child_process');
const { mkdtempSync, rmSync } = require('fs');
const { join } = require('os');

function scanRepo(githubUrl) {
  const tmpDir = mkdtempSync(join(require('os').tmpdir(), 'scan-'));

  try {
    // Clone (shallow, quiet)
    execSync(`git clone --depth 1 "${githubUrl}" "${tmpDir}/repo"`, {
      stdio: 'ignore',
      timeout: 30000
    });

    // Scan
    const output = execSync(
      `npx -y @elliotllliu/agent-shield scan "${tmpDir}/repo" --json`,
      { encoding: 'utf-8', timeout: 60000 }
    );

    return JSON.parse(output);
  } catch (error) {
    return {
      score: null,
      riskLevel: 'error',
      findings: [],
      error: error.message
    };
  } finally {
    rmSync(tmpDir, { recursive: true, force: true });
  }
}

// Usage
const result = scanRepo('https://github.com/owner/repo');
console.log(`Score: ${result.score}, Risk: ${result.riskLevel}`);
```

### Python

```python
import subprocess
import json
import tempfile
import shutil

def scan_repo(github_url):
    tmp_dir = tempfile.mkdtemp(prefix='scan-')

    try:
        # Clone
        subprocess.run(
            ['git', 'clone', '--depth', '1', github_url, f'{tmp_dir}/repo'],
            capture_output=True, timeout=30
        )

        # Scan
        result = subprocess.run(
            ['npx', '-y', '@elliotllliu/agent-shield', 'scan', f'{tmp_dir}/repo', '--json'],
            capture_output=True, text=True, timeout=60
        )

        return json.loads(result.stdout)
    except Exception as e:
        return {'score': None, 'riskLevel': 'error', 'error': str(e)}
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)

# Usage
result = scan_repo('https://github.com/owner/repo')
print(f"Score: {result['score']}, Risk: {result['riskLevel']}")
```

### Batch Scan Script

```bash
#!/bin/bash
# batch-scan.sh — Scan all repos listed in a file
# Usage: ./batch-scan.sh repos.txt results/
# repos.txt format: one GitHub URL per line

REPOS_FILE="${1:-repos.txt}"
RESULTS_DIR="${2:-./scan-results}"
PARALLEL="${3:-4}"

mkdir -p "$RESULTS_DIR"

scan_one() {
  local url="$1"
  local slug=$(echo "$url" | sed 's|.*/||' | sed 's|\.git$||')
  local tmp="/tmp/scan-$$-$slug"

  git clone --depth 1 "$url" "$tmp" 2>/dev/null
  npx -y @elliotllliu/agent-shield scan "$tmp" --json > "$RESULTS_DIR/$slug.json" 2>/dev/null
  rm -rf "$tmp"
  echo "✓ $slug ($(jq -r .score "$RESULTS_DIR/$slug.json")/100)"
}

export -f scan_one
export RESULTS_DIR

cat "$REPOS_FILE" | xargs -P "$PARALLEL" -I {} bash -c 'scan_one "$@"' _ {}

echo "Done. Results in $RESULTS_DIR/"
```

## Database Schema (Suggested)

```sql
CREATE TABLE skill_scans (
  id            SERIAL PRIMARY KEY,
  skill_slug    VARCHAR(255) NOT NULL,
  repo_url      VARCHAR(500),
  score         INTEGER,          -- 0-100, NULL if scan failed
  risk_level    VARCHAR(20),      -- low/moderate/high/critical/error
  files_scanned INTEGER,
  lines_scanned INTEGER,
  scan_time_ms  INTEGER,
  findings      JSONB,            -- Full findings array
  scanned_at    TIMESTAMP DEFAULT NOW(),
  UNIQUE(skill_slug)
);

-- Index for filtering
CREATE INDEX idx_risk ON skill_scans(risk_level);
CREATE INDEX idx_score ON skill_scans(score);
```

## Scan Scheduling

| Trigger | When | Scope |
|---------|------|-------|
| New skill indexed | Immediately | Single skill |
| Weekly cron | Every Sunday 03:00 UTC | All skills |
| User clicks "Re-scan" | On demand | Single skill |
| Repo updated (webhook) | On push event | Single skill |

## Edge Cases

| Situation | Behavior |
|-----------|----------|
| Empty repo | Returns `score: 100`, zero findings |
| Binary-only repo | Scans any text files found, ignores binaries |
| Very large repo (>100MB) | Use `--depth 1` clone; scan still works but takes longer |
| No internet | Works fine — AgentShield is 100% offline |
| Scan timeout | Set timeout to 60s per scan; catch error and mark as `"error"` |
| Private repo | Requires git auth; most skills are public |

## FAQ

**Q: Does AgentShield phone home?**
A: No. Zero network calls. Everything runs locally.

**Q: What file types are scanned?**
A: `.js`, `.ts`, `.py`, `.yaml`, `.yml`, `.json`, `.md`, `.sh`, `.toml`, and more.

**Q: How to handle false positives?**
A: Findings with `possibleFalsePositive: true` are likely benign (documentation examples, test files). You can either exclude them from the displayed score or show them with a "likely false positive" label.

**Q: Can I disable rules that don't apply?**
A: Yes. Use `--disable rule1,rule2`. Common: `--disable supply-chain` if you don't want npm CVE checks.

**Q: Dify plugins (.difypkg)?**
A: Supported. AgentShield auto-extracts and scans them.

---

**AgentShield** — MIT licensed, open source
- GitHub: https://github.com/elliotllliu/agent-shield
- npm: https://www.npmjs.com/package/@elliotllliu/agent-shield
