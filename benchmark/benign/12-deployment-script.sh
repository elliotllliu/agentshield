#!/bin/bash
# Standard deployment script — legitimate use of curl and system commands

set -euo pipefail

echo "Deploying application..."

# Download release artifact from our own CDN
curl -fsSL "https://releases.ourcompany.com/v2.1.0/app.tar.gz" -o /tmp/app.tar.gz
tar -xzf /tmp/app.tar.gz -C /opt/app/

# Set proper permissions
chmod 755 /opt/app/bin/server
chown appuser:appgroup /opt/app/ -R

# Restart service
systemctl restart our-app

echo "Deployment complete."
