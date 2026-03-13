# AgentShield × Agent Skills Hub — Integration Proposal

## Overview

Integrate AgentShield's security scanning into Agent Skills Hub (agentskillshub.top) to provide security scores and risk assessments for all 19,000+ listed skills, MCP servers, and tools.

**Result:** Agent Skills Hub becomes the first skill directory with built-in security verification.

---

## What Each Side Brings

| | Agent Skills Hub | AgentShield |
|---|---|---|
| **Assets** | 19,000+ skill index, user traffic, discovery UI | 30-rule security scanner, scoring engine, CI/CD tooling |
| **Needs** | Trust/safety differentiation vs competitors | Real-world adoption, distribution, visibility |

---

## Integration Architecture

```
┌─────────────────────────────────────────────────┐
│              Agent Skills Hub                    │
│                                                  │
│  ┌──────────┐    ┌──────────┐    ┌───────────┐  │
│  │  Skill   │    │  Skill   │    │  Skill    │  │
│  │  Listing │    │  Listing │    │  Listing  │  │
│  │          │    │          │    │           │  │
│  │ Score:92 │    │ Score:45 │    │ Score:78  │  │
│  │ 🟢 Safe  │    │ 🔴 Risk  │    │ 🟡 Review │  │
│  └────┬─────┘    └────┬─────┘    └─────┬─────┘  │
│       │               │               │         │
│       └───────────────┼───────────────┘         │
│                       │                          │
│              ┌────────▼────────┐                 │
│              │  Security DB    │                 │
│              │  (scan results) │                 │
│              └────────┬────────┘                 │
│                       │                          │
└───────────────────────┼──────────────────────────┘
                        │
                ┌───────▼───────┐
                │  AgentShield  │
                │  Scanner      │
                │               │
                │  npx scan     │
                │  --json       │
                └───────────────┘
```

---

## Core Features

### 1. Security Score Badge (每个 Skill 页面)

Each skill listing displays:

```
┌─────────────────────────────────────┐
│  🛡️ Security Score: 92/100         │
│  Risk Level: 🟢 Low Risk           │
│  Last Scanned: 2026-03-13          │
│  Scanned by AgentShield            │
│                                     │
│  ✅ No backdoors detected          │
│  ✅ No data exfiltration patterns  │
│  ✅ No prompt injection found      │
│  ⚠️ 1 medium: env variable access  │
└─────────────────────────────────────┘
```

**Score tiers:**

| Score | Badge | Meaning |
|-------|-------|---------|
| 90-100 | 🟢 Verified Safe | No high-risk findings |
| 70-89 | 🟡 Review Advised | Minor warnings, generally safe |
| 40-69 | 🟠 High Risk | Investigate before using |
| 0-39 | 🔴 Critical Risk | Do not install without review |
| — | ⏳ Pending | Not yet scanned |

### 2. Scan Pipeline (批量扫描流程)

```
GitHub Repo URL
      │
      ▼
┌─────────────┐
│  git clone  │  (shallow, depth=1)
│  to /tmp    │
└──────┬──────┘
       │
       ▼
┌──────────────────────────────┐
│  npx @elliotllliu/agent-shield  │
│  scan /tmp/repo --json       │
└──────┬───────────────────────┘
       │
       ▼
┌─────────────────┐
│  Parse JSON     │
│  Store to DB    │
│  {              │
│    score: 92,   │
│    risk: "low", │
│    findings: [] │
│  }              │
└──────┬──────────┘
       │
       ▼
┌─────────────────┐
│  Display on     │
│  skill page     │
└─────────────────┘
```

### 3. Search & Filter (搜索增强)

Users can:
- **Filter by security level**: "Show only 🟢 verified skills"
- **Sort by security score**: Highest score first
- **Filter out risky skills**: Hide 🔴 critical skills by default

### 4. Scan Report Page (详情页)

Each skill gets a dedicated security report page:

```
/skill/[slug]/security

├── Overall Score: 92/100
├── Risk Level: 🟢 Low Risk  
├── Scan Date: 2026-03-13
├── Files Scanned: 12
├── Lines Analyzed: 1,847
│
├── Findings (1)
│   └── 🟡 MEDIUM: env-leak
│       File: src/config.ts:15
│       Detail: Reads process.env.API_KEY
│       Risk: Environment variable accessed
│
├── Rules Passed (29/30)
│   ✅ backdoor
│   ✅ data-exfil
│   ✅ reverse-shell
│   ✅ prompt-injection
│   ✅ tool-shadowing
│   ✅ cross-file
│   ✅ attack-chain
│   ... (22 more)
│
└── Powered by AgentShield
    https://github.com/elliotllliu/agent-shield
```

---

## Technical Integration

### Option A: CLI-based (Simplest)

Hub's backend runs the scan directly:

```bash
# Install globally (one-time)
npm i -g @elliotllliu/agent-shield

# Scan a repo and get JSON output
agent-shield scan /path/to/cloned/repo --json
```

**JSON output format:**

```json
{
  "score": 92,
  "riskLevel": "low",
  "summary": {
    "filesScanned": 12,
    "linesAnalyzed": 1847,
    "scanTimeMs": 234
  },
  "findings": [
    {
      "rule": "env-leak",
      "severity": "medium",
      "file": "src/config.ts",
      "line": 15,
      "message": "Environment variable access with potential outbound HTTP",
      "snippet": "const key = process.env.API_KEY"
    }
  ],
  "passed": ["backdoor", "data-exfil", "reverse-shell", "..."]
}
```

### Option B: npm API (Programmatic)

```javascript
import { scan } from '@elliotllliu/agent-shield';

const result = await scan({
  path: '/path/to/repo',
  json: true,
  // Optional: disable specific rules
  disable: ['supply-chain']
});

// result.score → 92
// result.findings → [...]
// result.riskLevel → "low"
```

### Option C: GitHub Action (for user-submitted skills)

```yaml
- uses: elliotllliu/agent-shield@main
  with:
    path: './skills/'
    fail-under: '70'
```

---

## Scan Scheduling

| Trigger | When | Scope |
|---------|------|-------|
| **Initial batch** | One-time | All 19,000+ skills |
| **New skill added** | On index | Single skill |
| **Periodic re-scan** | Weekly/monthly | All skills (detect changes) |
| **On-demand** | User clicks "Re-scan" | Single skill |

### Batch Scan Estimates

| Metric | Estimate |
|--------|----------|
| Average scan time | ~200ms per skill |
| 19,000 skills | ~63 minutes total |
| Disk per clone | ~50MB avg (shallow) |
| Parallelism | 4-8 concurrent scans recommended |

---

## UI Mockup — Skill Card

```
┌──────────────────────────────────────────────┐
│                                              │
│  📦 awesome-mcp-filesystem          ⭐ 342  │
│  by modelcontextprotocol                     │
│                                              │
│  File system access for AI agents with       │
│  read, write, and search capabilities.       │
│                                              │
│  🟢 92/100  │  📅 Updated 3 days ago        │
│  Verified Safe  │  ⬇️ 12.4k installs        │
│                                              │
│  Tags: filesystem, mcp, file-access          │
│                                              │
└──────────────────────────────────────────────┘
```

---

## Branding & Attribution

On every scanned skill page:

```
🛡️ Security scan powered by AgentShield
   Open source: github.com/elliotllliu/agent-shield
```

- AgentShield logo + link on security badge
- "Powered by AgentShield" in footer of scan reports
- Joint blog post on launch: "We scanned 19,000 agent skills — here's what we found"

---

## Rollout Plan

| Phase | Timeline | Deliverable |
|-------|----------|-------------|
| **Phase 1** | Week 1 | Batch scan top 500 most popular skills, validate results |
| **Phase 2** | Week 2 | UI integration — badges on skill cards + detail pages |
| **Phase 3** | Week 3 | Full 19,000 skill scan, search filters |
| **Phase 4** | Week 4 | Launch blog post + social media push |
| **Ongoing** | Weekly | Re-scan cycle, new skill auto-scan |

---

## Open Questions

1. **Data source**: Skills are indexed from GitHub? Or user-submitted?
2. **Backend stack**: What language/framework? (for choosing integration option)
3. **Hosting**: Can the server run npx/node commands? Or need a separate scan worker?
4. **Branding**: "Powered by AgentShield" — positioning and placement preferences?
5. **Commercial**: Pure open-source collab? Or any monetization plans?

---

## Contact

- **AgentShield**: https://github.com/elliotllliu/agent-shield
- **npm**: https://www.npmjs.com/package/@elliotllliu/agent-shield
- **Maintainer**: Elliot Liu (@elliotllliu)
