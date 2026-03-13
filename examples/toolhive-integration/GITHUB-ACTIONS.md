# ToolHive × AgentShield Integration PoC

## GitHub Actions Workflow

Add this to `.github/workflows/security-scan.yml` in the ToolHive registry:

```yaml
name: AgentShield Security Scan

on:
  pull_request:
    paths:
      - 'examples/toolhive-registry.json'
      - '**/server.json'

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Scan registry servers
        run: node toolhive-agentshield-integration.mjs examples/toolhive-registry.json --fail-under 60
      
      - name: Upload scan results
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: security-reports
          path: /tmp/toolhive-scan-results/
      
      - name: Comment PR with results
        if: github.event_name == 'pull_request'
        uses: actions/github-script@v7
        with:
          script: |
            const fs = require('fs');
            const enrichment = JSON.parse(fs.readFileSync('/tmp/toolhive-scan-results/registry-enrichment.json'));
            let body = '## 🛡️ AgentShield Security Scan Results\n\n';
            body += '| Server | Score | Grade | High | Medium |\n';
            body += '|--------|-------|-------|------|--------|\n';
            for (const [name, data] of Object.entries(enrichment)) {
              const icon = data.security_grade === 'A' ? '✅' : data.security_grade === 'B' ? '🟡' : '🔴';
              body += `| ${name} | ${data.security_score}/100 | ${icon} ${data.security_grade} | ${data.high_findings} | ${data.medium_findings} |\n`;
            }
            github.rest.issues.createComment({
              owner: context.repo.owner,
              repo: context.repo.repo,
              issue_number: context.issue.number,
              body
            });
```

## Registry Enrichment

The integration outputs a `registry-enrichment.json` that can be merged into ToolHive's server metadata:

```json
{
  "fetch": {
    "security_score": 97,
    "security_grade": "A",
    "high_findings": 0,
    "medium_findings": 0,
    "scanned_at": "2026-03-13T15:45:00Z",
    "scanner": "agentshield@0.7.0"
  }
}
```

This data can power:
- **Portal UI**: Security badge per server
- **Registry API**: `GET /servers/{name}` includes `security_score`
- **CLI**: `thv run` shows security grade before deployment
