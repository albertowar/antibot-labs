"""
Round 3 attack — low-and-slow, distributed across hundreds of IPs

The attacker gives up on volume per IP entirely. A handful of target accounts
are attacked from a large pool of IPs, roughly one attempt per IP, paced like a
slow human. Per IP there is nothing to see: one or two failed logins, minutes
apart. The per-IP window is silent, the per-session stuffing-shape gate from
Round 2 never trips (each session fails only once or twice), and there are too
few events per session for timing regularity to mean anything.

What gives it away is the pivot to the *username*: each of the five target
accounts is hit from ~60 distinct IPs in an hour. No real account logs in from
60 IPs in an hour. That is the distinct-IP-per-user fan-out the cross-key
detector counts with a HyperLogLog.

    python attacks/round3_low_and_slow.py
"""

import os
import random
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
for _d in ("attacks", "demo_site"):
    sys.path.insert(0, os.path.join(os.path.dirname(HERE), _d))

from _common import BASE_TS, bot_ip, make_event

VICTIMS = [f"vip{v}@mail.example" for v in range(5)]
IPS_PER_VICTIM = 60
WINDOW_S = 1800.0   # spread over half an hour (one cross-key window)


def generate():
    rng = random.Random(303)
    events = []
    idx = 0
    for v, victim in enumerate(VICTIMS):
        for j in range(IPS_PER_VICTIM):
            ip = bot_ip(idx)
            sid = f"bot-slow-{idx}"
            idx += 1
            n_tries = 1 if rng.random() < 0.7 else 2
            start = BASE_TS + rng.uniform(0, WINDOW_S)
            for k in range(n_tries):
                ts = start + k * 70.0  # ~once a minute if it retries
                events.append(make_event(
                    ts, sid, ip, "/api/login", status=401, method="POST",
                    user=victim, actor="bot:low_and_slow", ua="okhttp/4.12"))
    return events


if __name__ == "__main__":
    from _common import deliver
    events = generate()
    deliver(events, f"low_and_slow: wrote {len(events)} failed logins across "
                    f"{len(VICTIMS)} accounts from ~{IPS_PER_VICTIM} IPs each")
