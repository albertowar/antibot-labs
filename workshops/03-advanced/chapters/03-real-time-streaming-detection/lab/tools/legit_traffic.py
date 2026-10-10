"""
W3 Ch3 — Legitimate-traffic simulator (40 synthetic customers)

Humans are the cost side of every round. These 40 shoppers browse, load assets,
pause for human-length and irregular amounts of time, log in successfully, and
some check out. None of them fails a login, each uses one IP, and each uses
their own account — so a correct detector should never flag them. Every
checkpoint runs these next to the attack and reports how many got caught.

The `actor` field is ground truth ("human:shopper"); only the scoreboard reads
it. Timings are seeded per customer, so the false-positive count is stable.

    python tools/legit_traffic.py   # prints a one-line summary of the cohort
"""

import random

import lab  # noqa: F401  (sets sys.path)
from _common import BASE_TS, HUMAN_NET, make_event

N_CUSTOMERS = 40
PRODUCTS = [f"/product/{k}" for k in range(1, 9)]


def generate():
    events = []
    for c in range(N_CUSTOMERS):
        rng = random.Random(1000 + c)
        ip = f"{HUMAN_NET}{c + 1}"
        sid = f"human-{c}"
        user = f"cust{c}@mail.example"
        t = BASE_TS + rng.uniform(0, 120)

        def step(path, status=200, method="GET", u=""):
            nonlocal t
            events.append(make_event(t, sid, ip, path, status=status,
                                     method=method, user=u, actor="human:shopper",
                                     ua="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                                        "Chrome/141.0.0.0 Safari/537.36"))
            t += rng.uniform(1.5, 8.0)  # human, irregular

        step("/")
        step("/static/app.js")
        step("/static/style.css")
        step("/api/products")
        for _ in range(rng.randint(2, 4)):
            step(rng.choice(PRODUCTS))
            if rng.random() < 0.5:
                step("/static/thumb.png")
        if rng.random() < 0.4:
            step("/api/search?q=shoe")
        step("/api/login", status=200, method="POST", u=user)  # success
        if rng.random() < 0.5:
            step("/api/checkout", status=200, method="POST", u=user)
    return events


if __name__ == "__main__":
    events = generate()
    sids = {e["sid"] for e in events}
    print(f"legit_traffic: {len(events)} events across {len(sids)} customers, "
          f"0 failed logins by construction")
