"""
Round 1 attack — single-IP micro-burst

The crudest credential-stuffing shape: one client hammering /api/login as fast
as it can. 150 failed logins from one IP in ten seconds, evenly spaced because
a tight loop with a fixed sleep is regular. The static rate limiter from W1 Ch2
may split this across its fixed-window boundary; the sliding-window detector on
the stream does not. This is the burst that finishes long before a session-level
or batch scorer would ever look (Round 0 shows that gap).

Run standalone to write the events and see the shape:
    python attacks/round1_microburst.py
"""

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
for _d in ("attacks", "demo_site"):
    sys.path.insert(0, os.path.join(os.path.dirname(HERE), _d))

from _common import BASE_TS, bot_ip, make_event

N_REQUESTS = 150
RATE_HZ = 15.0  # requests per second (tight loop)


def generate():
    ip = bot_ip(0)
    sid = "bot-microburst"
    events = []
    for i in range(N_REQUESTS):
        ts = BASE_TS + i / RATE_HZ
        events.append(make_event(
            ts, sid, ip, "/api/login", status=401, method="POST",
            user=f"victim{i}@mail.example", actor="bot:microburst",
            ua="python-requests/2.34.0"))
    return events


if __name__ == "__main__":
    from _common import deliver
    events = generate()
    deliver(events, f"microburst: wrote {len(events)} events from one IP over "
                    f"{N_REQUESTS / RATE_HZ:.1f}s")
