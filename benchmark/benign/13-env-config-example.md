# Configuration Guide

## Environment Variables

Set these environment variables before running:

```bash
export DATABASE_URL="postgres://user:password@localhost:5432/mydb"
export API_KEY="your-api-key-here"
export AWS_ACCESS_KEY_ID="your-access-key"
export SECRET_KEY="replace-with-your-secret"
```

**Important:** Never commit real credentials. Use a `.env` file 
(added to `.gitignore`) or a secrets manager like HashiCorp Vault.

## Example .env file
```
# Replace these placeholder values with your actual credentials
OPENAI_API_KEY=sk-replace-me
GITHUB_TOKEN=ghp_replace-me
```

These are placeholder values only. See your team lead for actual credentials.
