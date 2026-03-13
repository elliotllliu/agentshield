# AgentShield Benchmark Results

Generated: 2026-03-13T15:06:51.271Z
Duration: 974ms

## Summary

| Metric | Value |
|--------|-------|
| Malicious samples | 63 |
| Benign samples | 66 |
| True Positives | 63/63 |
| False Negatives | 0 |
| True Negatives | 66/66 |
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
| malicious/32-implicit-tool-poisoning.yaml | ✅ | 0 | 5 | 0 | prompt-injection, multilang-injection |
| malicious/33-memory-poisoning.md | ✅ | 0 | 3 | 0 | multilang-injection, prompt-injection |
| malicious/35-full-kill-chain.py | ✅ | 6 | 2 | 0 | data-exfil, cross-file, attack-chain, env-leak, sensitive-read |
| malicious/36-sql-injection.py | ✅ | 1 | 1 | 0 | ast-sql-injection, python-security |
| malicious/37-ssti-template.py | ✅ | 0 | 2 | 0 | python-security |
| malicious/38-pickle-deser.py | ✅ | 2 | 2 | 0 | ast-deserialization, python-security |
| malicious/39-eval-input.py | ✅ | 2 | 8 | 0 | backdoor, python-security, ast-code-exec, ast-dynamic-import |
| malicious/40-description-exfil.md | ✅ | 0 | 0 | 0 | sensitive-read, prompt-injection, skill-risks |
| malicious/41-credential-exfil.js | ✅ | 0 | 2 | 0 | data-exfil, env-leak, sensitive-read |
| malicious/42-chinese-injection.md | ✅ | 0 | 0 | 0 | sensitive-read, prompt-injection |
| malicious/43-french-injection.md | ✅ | 0 | 0 | 0 | sensitive-read, prompt-injection, skill-risks |
| malicious/44-japanese-injection.md | ✅ | 0 | 0 | 0 | sensitive-read, prompt-injection, skill-risks |
| malicious/45-hidden-revshell.sh | ✅ | 0 | 1 | 0 | reverse-shell |
| malicious/46-mcp-path-traversal.md | ✅ | 0 | 0 | 0 | prompt-injection |
| malicious/47-postinstall-backdoor.js | ✅ | 1 | 1 | 0 | backdoor, skill-risks |
| malicious/48-spanish-injection.md | ✅ | 0 | 0 | 0 | sensitive-read, prompt-injection |
| malicious/49-zero-width-hidden.md | ✅ | 0 | 0 | 0 | prompt-injection |
| malicious/50-ssh-key-exfil.py | ✅ | 1 | 0 | 0 | cross-file |
| malicious/51-remote-code-exec.js | ✅ | 0 | 1 | 0 | backdoor |
| malicious/52-tool-desc-injection.yaml | ✅ | 0 | 4 | 0 | prompt-injection, description-integrity |
| malicious/53-hidden-miner.py | ✅ | 0 | 1 | 0 | crypto-mining |
| malicious/54-persistence-cron.sh | ✅ | 1 | 0 | 0 | backdoor, sensitive-read, skill-risks |
| malicious/55-env-dump-exfil.py | ✅ | 1 | 0 | 0 | cross-file |
| malicious/56-go-injection.go | ✅ | 0 | 2 | 0 | go-rust-security |
| malicious/57-rust-injection.rs | ✅ | 0 | 2 | 0 | go-rust-security |
| malicious/58-dify-eval-llm-output.py | ✅ | 2 | 4 | 0 | backdoor, python-security, ast-code-exec |
| malicious/59-dify-exec-llm-code.py | ✅ | 1 | 2 | 0 | backdoor, python-security, ast-code-exec |
| malicious/60-bipia-indirect-injection.yaml | ✅ | 0 | 2 | 0 | prompt-injection |
| malicious/61-injecagent-result-injection.py | ✅ | 0 | 2 | 0 | prompt-injection, sensitive-read |
| malicious/62-cve-sandbox-escape.js | ✅ | 0 | 2 | 0 | backdoor |
| malicious/63-cve-container-escape.py | ✅ | 1 | 1 | 0 | cross-file, backdoor, sensitive-read, skill-risks |
| malicious/64-mcp-rug-pull.py | ✅ | 1 | 3 | 0 | backdoor, python-security, ast-cmd-injection, ast-code-exec, sensitive-read |

## Benign Samples

| File | Clean | Critical | Warning | Score |
|------|-------|----------|---------|-------|
| benign/01-weather-tool.md | ✅ | 0 | 0 | 48.4 |
| benign/02-code-formatter.md | ✅ | 0 | 0 | 48.4 |
| benign/03-git-helper.md | ✅ | 0 | 0 | 48.4 |
| benign/04-database-query.md | ✅ | 0 | 0 | 48.4 |
| benign/05-translation.md | ✅ | 0 | 0 | 48.4 |
| benign/06-image-resizer.md | ✅ | 0 | 0 | 48.4 |
| benign/07-markdown-preview.md | ✅ | 0 | 0 | 48.4 |
| benign/08-calculator.md | ✅ | 0 | 0 | 48.4 |
| benign/09-spell-checker.md | ✅ | 0 | 0 | 48.4 |
| benign/10-file-search.md | ✅ | 0 | 0 | 48.4 |
| benign/11-json-validator.md | ✅ | 0 | 0 | 48.4 |
| benign/11-security-tutorial.md | ✅ | 0 | 0 | 48.4 |
| benign/12-deployment-script.sh | ✅ | 0 | 0 | 48.4 |
| benign/12-test-generator.md | ✅ | 0 | 0 | 48.4 |
| benign/13-docker-helper.md | ✅ | 0 | 0 | 48.4 |
| benign/13-env-config-example.md | ✅ | 0 | 0 | 48.4 |
| benign/14-changelog.md | ✅ | 0 | 0 | 48.4 |
| benign/15-api-client.md | ✅ | 0 | 0 | 48.4 |
| benign/16-log-analyzer.py | ✅ | 0 | 0 | 48.4 |
| benign/17-mcp-tool-legit.json | ✅ | 0 | 2 | 48.4 |
| benign/18-cron-healthcheck.py | ✅ | 0 | 1 | 48.4 |
| benign/19-base64-codec.py | ✅ | 0 | 0 | 48.4 |
| benign/20-subprocess-tool.py | ✅ | 0 | 2 | 48.4 |
| benign/21-multilang-readme.md | ✅ | 0 | 0 | 48.4 |
| benign/22-normal-tool.yaml | ✅ | 0 | 0 | 48.4 |
| benign/23-csv-parser.py | ✅ | 0 | 0 | 48.4 |
| benign/24-string-utils.js | ✅ | 0 | 0 | 48.4 |
| benign/25-git-branch-clean.sh | ✅ | 0 | 0 | 48.4 |
| benign/26-date-formatter.js | ✅ | 0 | 0 | 48.4 |
| benign/27-regex-tester.py | ✅ | 0 | 0 | 48.4 |
| benign/28-markdown-toc.md | ✅ | 0 | 0 | 48.4 |
| benign/29-color-converter.py | ✅ | 0 | 0 | 48.4 |
| benign/30-jwt-decoder.js | ✅ | 0 | 0 | 48.4 |
| benign/31-test-helper.md | ✅ | 0 | 0 | 48.4 |
| benign/32-yaml-json-converter.py | ✅ | 0 | 0 | 48.4 |
| benign/33-docker-helper.sh | ✅ | 0 | 0 | 48.4 |
| benign/34-http-status.js | ✅ | 0 | 0 | 48.4 |
| benign/35-diff-viewer.py | ✅ | 0 | 0 | 48.4 |
| benign/36-mcp-calculator.json | ✅ | 0 | 0 | 48.4 |
| benign/37-link-checker.py | ✅ | 0 | 0 | 48.4 |
| benign/38-array-utils.js | ✅ | 0 | 0 | 48.4 |
| benign/39-hash-calc.py | ✅ | 0 | 0 | 48.4 |
| benign/40-emoji-picker.md | ✅ | 0 | 0 | 48.4 |
| benign/41-port-check.js | ✅ | 0 | 1 | 48.4 |
| benign/42-text-stats.py | ✅ | 0 | 0 | 48.4 |
| benign/43-disk-usage.sh | ✅ | 0 | 0 | 48.4 |
| benign/43-snippet-manager.md | ✅ | 0 | 0 | 48.4 |
| benign/44-disk-usage.sh | ✅ | 0 | 0 | 48.4 |
| benign/44-env-loader.js | ✅ | 0 | 0 | 48.4 |
| benign/45-image-meta.py | ✅ | 0 | 0 | 48.4 |
| benign/45-md-to-html.js | ✅ | 0 | 0 | 48.4 |
| benign/46-ip-validator.py | ✅ | 0 | 0 | 48.4 |
| benign/46-snippet-manager.md | ✅ | 0 | 0 | 48.4 |
| benign/47-cron-parser.py | ✅ | 0 | 0 | 48.4 |
| benign/47-mcp-git-log.json | ✅ | 0 | 0 | 48.4 |
| benign/48-semver.js | ✅ | 0 | 0 | 48.4 |
| benign/48-system-info.js | ✅ | 0 | 0 | 48.4 |
| benign/49-password-check.py | ✅ | 0 | 0 | 48.4 |
| benign/49-password-strength.py | ✅ | 0 | 0 | 48.4 |
| benign/50-commit-helper.md | ✅ | 0 | 0 | 48.4 |
| benign/50-cron-parser.md | ✅ | 0 | 0 | 48.4 |
| benign/51-levenshtein.js | ✅ | 0 | 0 | 48.4 |
| benign/52-go-server.go | ✅ | 0 | 0 | 48.4 |
| benign/53-rust-utils.rs | ✅ | 0 | 0 | 48.4 |
| benign/54-feishu-plugin.ts | ✅ | 0 | 0 | 48.4 |
| benign/55-feishu-auth.ts | ✅ | 0 | 0 | 48.4 |
