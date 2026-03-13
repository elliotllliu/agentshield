# AgentShield Benchmark Results

Generated: 2026-03-13T06:29:11.074Z
Duration: 778ms

## Summary

| Metric | Value |
|--------|-------|
| Malicious samples | 33 |
| Benign samples | 24 |
| True Positives | 33/33 |
| False Negatives | 0 |
| True Negatives | 24/24 |
| False Positives | 0 |
| **Recall** | **100.0%** |
| **Precision** | **100.0%** |
| **F1 Score** | **100.0%** |
| **FPR** | **0.0%** |
| **Accuracy** | **100.0%** |

## Malicious Samples

| File | Detected | Critical | Warning | Score | Rules |
|------|----------|----------|---------|-------|-------|
| malicious/01-instruction-override.md | ✅ | 0 | 0 | 0 | prompt-injection |
| malicious/02-identity-manipulation.md | ✅ | 0 | 1 | 0 | multilang-injection, prompt-injection |
| malicious/03-system-prompt-attacks.md | ✅ | 0 | 0 | 0 | prompt-injection |
| malicious/04-hidden-instructions.md | ✅ | 0 | 0 | 0 | sensitive-read, prompt-injection |
| malicious/05-behavioral-hijacking.md | ✅ | 0 | 2 | 0 | tool-shadowing, multilang-injection, prompt-injection |
| malicious/06-tool-poisoning.md | ✅ | 0 | 0 | 0 | prompt-injection |
| malicious/07-data-exfiltration.md | ✅ | 0 | 0 | 0 | sensitive-read, prompt-injection |
| malicious/08-encoding-evasion.md | ✅ | 0 | 0 | 0 | prompt-injection |
| malicious/09-advanced-attacks.md | ✅ | 0 | 0 | 0 | sensitive-read, prompt-injection |
| malicious/10-backdoor-eval.py | ✅ | 3 | 8 | 0 | backdoor, python-security, ast-code-exec |
| malicious/10-mcp-config-attacks.md | ✅ | 0 | 3 | 0 | tool-shadowing, multilang-injection, sensitive-read, prompt-injection |
| malicious/11-credential-leak.py | ✅ | 0 | 3 | 0 | credential-hardcode, sensitive-read |
| malicious/11-subtle-injection.md | ✅ | 0 | 0 | 0 | prompt-injection |
| malicious/12-crypto-miner.py | ✅ | 0 | 6 | 0 | crypto-mining, ast-cmd-injection |
| malicious/12-suspicious-urls.md | ✅ | 0 | 0 | 0 | prompt-injection |
| malicious/13-data-exfil.py | ✅ | 4 | 1 | 0 | data-exfil, cross-file, attack-chain, env-leak, sensitive-read, skill-risks |
| malicious/13-skill-risks.md | ✅ | 0 | 0 | 0 | skill-risks |
| malicious/14-env-exfil.py | ✅ | 1 | 0 | 0 | cross-file, sensitive-read |
| malicious/14-multilang-injection.md | ✅ | 0 | 0 | 0 | prompt-injection |
| malicious/15-reverse-shell.sh | ✅ | 0 | 2 | 0 | reverse-shell |
| malicious/15-toxic-flow-config.json | ✅ | 0 | 2 | 0 |  |
| malicious/16-phone-home.py | ✅ | 1 | 3 | 0 | backdoor, phone-home, python-security, ast-code-exec |
| malicious/17-obfuscated-payload.py | ✅ | 3 | 6 | 0 | backdoor, python-security, ast-code-exec |
| malicious/18-supply-chain.sh | ✅ | 2 | 0 | 0 | backdoor |
| malicious/19-ssrf.py | ✅ | 0 | 1 | 0 | network-ssrf |
| malicious/20-tool-shadow.md | ✅ | 0 | 0 | 0 | prompt-injection |
| malicious/21-toxic-flow.md | ✅ | 0 | 0 | 0 | prompt-injection |
| malicious/22-skill-risks.md | ✅ | 0 | 0 | 0 | skill-risks |
| malicious/23-sensitive-read.py | ✅ | 0 | 0 | 0 | sensitive-read, skill-risks |
| malicious/24-privilege-escalation.sh | ✅ | 1 | 0 | 0 | backdoor, sensitive-read, skill-risks |
| malicious/31-multilang-injection.md | ✅ | 0 | 4 | 0 | multilang-injection, prompt-injection |
| malicious/33-memory-poisoning.md | ✅ | 0 | 3 | 0 | multilang-injection, prompt-injection |
| malicious/35-full-kill-chain.py | ✅ | 6 | 2 | 0 | data-exfil, cross-file, attack-chain, env-leak, sensitive-read |

## Benign Samples

| File | Clean | Critical | Warning | Score |
|------|-------|----------|---------|-------|
| benign/01-weather-tool.md | ✅ | 0 | 0 | 54 |
| benign/02-code-formatter.md | ✅ | 0 | 0 | 54 |
| benign/03-git-helper.md | ✅ | 0 | 0 | 54 |
| benign/04-database-query.md | ✅ | 0 | 0 | 54 |
| benign/05-translation.md | ✅ | 0 | 0 | 54 |
| benign/06-image-resizer.md | ✅ | 0 | 0 | 54 |
| benign/07-markdown-preview.md | ✅ | 0 | 0 | 54 |
| benign/08-calculator.md | ✅ | 0 | 0 | 54 |
| benign/09-spell-checker.md | ✅ | 0 | 0 | 54 |
| benign/10-file-search.md | ✅ | 0 | 0 | 54 |
| benign/11-json-validator.md | ✅ | 0 | 0 | 54 |
| benign/11-security-tutorial.md | ✅ | 0 | 0 | 54 |
| benign/12-deployment-script.sh | ✅ | 0 | 0 | 54 |
| benign/12-test-generator.md | ✅ | 0 | 0 | 54 |
| benign/13-docker-helper.md | ✅ | 0 | 0 | 54 |
| benign/13-env-config-example.md | ✅ | 0 | 0 | 54 |
| benign/14-changelog.md | ✅ | 0 | 0 | 54 |
| benign/15-api-client.md | ✅ | 0 | 0 | 54 |
| benign/16-log-analyzer.py | ✅ | 0 | 0 | 54 |
| benign/17-mcp-tool-legit.json | ✅ | 0 | 2 | 54 |
| benign/18-cron-healthcheck.py | ✅ | 0 | 1 | 54 |
| benign/19-base64-codec.py | ✅ | 0 | 0 | 54 |
| benign/20-subprocess-tool.py | ✅ | 0 | 2 | 54 |
| benign/21-multilang-readme.md | ✅ | 0 | 0 | 54 |
