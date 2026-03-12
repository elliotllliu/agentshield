# 🛡️ ClawHub Security Report — Top Skills Audit

> Scanned by [AgentShield](https://github.com/elliotllliu/agentshield) v0.2.1
> Date: 2026-03-12

## Summary

We scanned **9 of the most popular skill repositories** on ClawHub, covering skills with **700K+ combined installs**. The goal is to understand the **security surface area** of the AI agent skill ecosystem — not to label any specific project as "insecure."

> ⚠️ **Important context:** AgentShield uses pattern-based static analysis. It flags code patterns that *could* be dangerous (e.g., reading credentials + making HTTP requests), but **many flagged patterns are legitimate** (API integrations, deploy scripts, etc.). Findings should be reviewed manually — a low score does not mean a project is malicious.

| Metric | Value |
|--------|-------|
| Repos scanned | 9 |
| Average raw score | **47/100** |
| Repos with findings requiring review | 6 (67%) |
| Clean (no findings) | 3 (33%) |

## Results

| Repository | Installs | Raw Score | Findings | Assessment |
|------------|----------|-----------|----------|------------|
| vercel-labs/agent-skills | 157K | 0 | 6 critical | ✅ **False positives** — deploy scripts legitimately use `curl` to Vercel API |
| obra/superpowers | 94K | 0 | 3 crit, 25 warn | ⚠️ **Mostly test code** — server.test.js has HTTP + env patterns; render script uses exec() |
| coreyhaines31/marketingskills | 42K | 0 | 122 crit, 206 warn | ⚠️ **By design** — 100+ CRM/analytics CLI tools each read API keys from env vars |
| expo/skills | 11K | 5 | 1 crit, 7 warn | ⚠️ **Legitimate** — fetch script reads env for CI/CD workflow |
| anthropics/skills | 36K | 35 | 1 crit, 4 warn | ⚠️ **Template code** — generator_template.js contains exec() for rendering |
| remotion-dev/skills | 140K | 80 | 2 warn | ✅ **Low risk** — minor warnings only |
| squirrelscan/skills | 34K | 100 | 0 | ✅ **Clean** — pure SKILL.md content |
| google-labs-code/stitch-skills | 63K | 100 | 0 | ✅ **Clean** — well-structured, no executable patterns |
| supercent-io/skills-template | 106K | 100 | 0 | ✅ **Clean** — safe templates |

## Detailed Analysis

### vercel-labs/agent-skills — False Positives (Not Malicious)

All 6 critical findings come from `skills/deploy-to-vercel/resources/deploy.sh` and `deploy-codex.sh`. These are **deployment scripts** — their entire purpose is to:
1. Package code into a tarball
2. POST it to the Vercel deployment API via `curl`
3. Poll the preview URL for deployment status

```bash
# This is NORMAL deploy behavior, not data exfiltration:
RESPONSE=$(curl -s -X POST "$DEPLOY_ENDPOINT" -F "file=@$TARBALL" -F "framework=$FRAMEWORK")
HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$PREVIEW_URL")
```

**Verdict:** ✅ Safe. The patterns are inherent to deployment tooling. This highlights a limitation of pattern-based scanning — it cannot distinguish intent.

### coreyhaines31/marketingskills — High Volume, Low Risk

122 critical findings sound alarming, but they're all the same pattern repeated across 100+ CRM/analytics CLI tools:

```javascript
const apiKey = process.env.ACTIVECAMPAIGN_API_KEY;  // reads API key
fetch(`https://api.activecampaign.com/...`, { headers: { 'Api-Token': apiKey } });  // calls API
```

Each tool is a thin wrapper around a marketing API. Reading an API key from env vars and sending it to the correct API endpoint is standard practice. The pattern is identical to data exfiltration at a code level, but the intent is legitimate.

**Verdict:** ⚠️ Review recommended. While each individual tool is likely safe, the sheer volume of credential access (100+ different API keys) means users should understand what they're granting access to.

### obra/superpowers — Mostly Test Code

3 critical findings:
- `server.test.js` — test file with HTTP requests + env vars (expected in tests)
- `render-graphs.js` — uses `exec()` to run Python for graph rendering

**Verdict:** ⚠️ Low concern. Test files shouldn't be flagged in production assessments, and exec() in a rendering utility is a known pattern.

### anthropics/skills — Template with exec()

1 critical finding in `generator_template.js` — a code generation template that contains `exec()`. This is part of an algorithmic art skill's template, not runtime code.

**Verdict:** ⚠️ Low concern. Template code containing exec() patterns.

## What This Tells Us

### The real insight isn't about these specific repos

These are all **legitimate, well-maintained projects** by reputable organizations (Vercel, Anthropic, Expo, Google Labs). The findings are almost entirely false positives or expected patterns.

**The real takeaway is:** if a *malicious* skill used the exact same code patterns, it would be indistinguishable from these legitimate tools. The AI agent skill ecosystem currently lacks:

1. **Permission declarations** — skills don't declare what they need access to
2. **Sandboxing** — skills run with full access to the host environment
3. **Review process** — anyone can publish a skill without security review

### Legitimate patterns that look dangerous

| Pattern | Legitimate Use | Malicious Use |
|---------|---------------|--------------|
| `env.API_KEY` + `fetch()` | API integration | Credential theft |
| `$(curl ...)` | Deploy scripts | Command injection |
| `exec()` + user input | Build tools | Remote code execution |
| `readFileSync` + `fetch` | File processing | Data exfiltration |

This is why automated scanning is a starting point, not a final verdict.

## Recommendations

### For Skill Authors
1. **Add `permissions` to SKILL.md** — declare what your skill needs
2. **Separate concerns** — keep deploy/build scripts in clearly labeled directories
3. **Document credential usage** — explain which env vars are needed and why
4. **Add AgentShield to CI** — not to block merges, but to track security surface area

### For Skill Consumers
1. **Scan before installing** — `npx @elliotllliu/agentshield scan ./skill/`
2. **Review findings in context** — a deploy skill using `curl` is normal
3. **Be cautious with unknown authors** — verified orgs (Vercel, Anthropic) have reputation at stake

### For the Ecosystem
1. **Standardize permission declarations** in SKILL.md
2. **Support skill sandboxing** — limit what skills can access
3. **Automated scanning as a signal**, not a gate — provide context, not just scores

## Methodology & Limitations

- **Tool:** [AgentShield](https://github.com/elliotllliu/agentshield) v0.2.1
- **Rules:** 16 security rules (pattern-based static analysis)
- **Scope:** Full repository scan (all files, not just SKILL.md)

### Known Limitations
- **False positives:** Pattern matching cannot determine intent. A legitimate `fetch()` call looks identical to data exfiltration at the code level.
- **No AST analysis:** Current rules use regex patterns, not abstract syntax trees. This means some context is lost.
- **Test code included:** Test files are scanned alongside production code, which inflates finding counts.
- **Raw scores are directional:** A low score means "patterns worth reviewing," not "this project is malicious."

## Scan Your Own Skills

```bash
npx @elliotllliu/agentshield scan ./my-skill/
```

---

*This report highlights security patterns for educational purposes. It does not claim any scanned project is malicious. All analyzed projects are open-source and maintained by reputable organizations.*
