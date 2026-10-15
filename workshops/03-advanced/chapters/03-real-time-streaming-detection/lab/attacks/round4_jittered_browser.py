"""
Round 4 attack: jittered, page-viewing, browser-like stuffing.

The attacker now looks human from every single angle. Each session comes from its own address
(beats the window), views a few pages before it tries a login (beats the stuffing-shape gate),
jitters its timing into the human range (beats regularity), and rotates accounts so no one
account fans out (beats the cross-key join). Every detector sees only a weak signal.

Most sessions still try four stolen credentials, because stuffing means trying them. That
residual (failing logins while a campaign is live on the stream) is what the composite catches
through its global campaign term. A patient quarter tries one credential per session and keeps
every term low: those get through, and that honest residual is the hand-off to W3 Ch4.

    python attacks/round4_jittered_browser.py
"""

import random

from _common import CHROME_UA, execute, finish, login, page, username, wrong_password, world_pool

N_SESSIONS = 80
PATIENT_FRACTION = 0.25
TRIES = 4


def run():
    rng = random.Random(404)
    ips = world_pool("residential_proxy")[:N_SESSIONS]
    plan = []
    for i, ip in enumerate(ips):
        key = f"jit-{i}"
        t = rng.uniform(0, 12)
        steps = [page(0, key, ip, p) for p in ("/", "/products", f"/product/p{1 + i % 100:03d}", "/products?category=packs")]
        steps += [login(0, key, ip, username(100 + (i * TRIES + k) % 200), wrong_password(i * 10 + k))
                  for k in range(1 if rng.random() < PATIENT_FRACTION else TRIES)]
        for s in steps:
            plan.append((t,) + s[1:])
            t += rng.uniform(0.3, 1.2)               # jittered, human-range gaps
    return execute(plan, "bot:jittered", CHROME_UA)


if __name__ == "__main__":
    finish(run())
