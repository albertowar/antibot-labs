"""
Round 2 attack — the burst, spread across rotating IPs

Round 1 keyed on the source IP, so the attacker spreads the same campaign over
many IPs. Here, 40 IPs each make four failed logins over a two-minute window.
Per IP that is four requests in 120s — far under the per-IP window threshold,
so Round 1's detector sees nothing. But the endpoint is still taking 160 failed
logins from 40 distinct IPs, which is what the sketches in Round 2 measure.

The attempts are interleaved in time (each IP's four tries are spread across the
window), so the campaign is visible on the stream as it happens, not all at the
end.

    python attacks/round2_ip_rotation.py
"""

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
for _d in ("attacks", "demo_site"):
    sys.path.insert(0, os.path.join(os.path.dirname(HERE), _d))

from _common import BASE_TS, bot_ip, make_event

N_IPS = 40
TRIES_PER_IP = 4
SPACING_S = 30.0   # seconds between a single IP's attempts


def generate():
    events = []
    for i in range(N_IPS):
        ip = bot_ip(i)
        sid = f"bot-rot-{i}"
        offset = (i % 30)  # stagger starts so attempts interleave across IPs
        for k in range(TRIES_PER_IP):
            ts = BASE_TS + offset + k * SPACING_S
            events.append(make_event(
                ts, sid, ip, "/api/login", status=401, method="POST",
                user=f"stuff{i}_{k}@mail.example", actor="bot:ip_rotation",
                ua="curl/8.9.0"))
    return events


if __name__ == "__main__":
    from _common import deliver
    events = generate()
    deliver(events, f"ip_rotation: wrote {len(events)} failed logins from {N_IPS} IPs "
                    f"({TRIES_PER_IP} each) — under any per-IP rate limit")
