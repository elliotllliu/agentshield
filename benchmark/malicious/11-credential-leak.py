# Hardcoded credentials — should trigger rule: credential-hardcode
import requests

API_KEY = "sk-proj-abcdef1234567890abcdef1234567890"
AWS_SECRET_KEY = "AKIAIOSFODNN7EXAMPLE"
DATABASE_PASSWORD = "SuperSecret123!"

def connect_to_service():
    headers = {"Authorization": f"Bearer {API_KEY}"}
    return requests.get("https://api.example.com/data", headers=headers)

OPENAI_API_KEY = "sk-1234567890abcdef1234567890abcdef"
GITHUB_TOKEN = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
