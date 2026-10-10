"""
Round 4 attack — jittered, asset-loading, browser-like stuffing

The attacker now looks human from every single angle. Each session comes from
its own IP (beats the window), loads a couple of static assets and browses a
product (beats the stuffing-shape gate), jitters its timing into the human range
(beats regularity), and rotates usernames so no one account fans out (beats the
cross-key join). Every detector sees only a weak signal.

Most sessions still fail two logins, because stuffing means trying stolen
credentials. That residual — failing logins while a campaign is live on the
stream — is what the composite catches through its global campaign term. A
patient minority fails only once and keeps every term low; those get through,
and that honest residual is the hand-off to W3 Ch4.

    python attacks/round4_jittered_browser.py
"""

import os
import random
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
for _d in ("attacks", "demo_site"):
    sys.path.insert(0, os.path.join(os.path.dirname(HERE), _d))

from _common import BASE_TS, bot_ip, make_event

N_SESSIONS = 80
PATIENT_FRACTION = 0.25   # this share fails only once and slips the composite
ASSETS = ["/static/app.js", "/static/style.css"]


def generate():
    rng = random.Random(404)
    events = []
    for i in range(N_SESSIONS):
        ip = bot_ip(i)
        sid = f"bot-jit-{i}"
        patient = rng.random() < PATIENT_FRACTION
        t = BASE_TS + rng.uniform(0, 90)
        ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/141.0.0.0 Safari/537.36"

        def step(path, status=200, method="GET", user=""):
            nonlocal t
            events.append(make_event(t, sid, ip, path, status=status,
                                     method=method, user=user,
                                     actor="bot:jittered", ua=ua))
            t += rng.uniform(1.5, 6.0)  # jittered, human-range gaps

        step("/")
        step(ASSETS[0])
        step("/api/products")
        step(ASSETS[1])
        n_fail = 1 if patient else 2
        for k in range(n_fail):
            step("/api/login", status=401, method="POST",
                 user=f"jit{i}_{k}@mail.example")
    return events


if __name__ == "__main__":
    from _common import deliver
    events = generate()
    deliver(events, f"jittered_browser: wrote {len(events)} events across {N_SESSIONS} "
                    f"browser-like sessions ({int(PATIENT_FRACTION*100)}% patient)")
