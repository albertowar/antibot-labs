"""
Round 4 attack: the integrated assault, the whole kill chain (W3, every layer).

The scalper stops playing one move at a time and runs a real operation: three stages, each from its own session and
address, the way a division of labour works.

    1. recon     scrape the catalogue with one GraphQL batch (a hundred aliases) to find the drop
    2. evade     poll the drop page low-and-slow, to stay under every rate limit while waiting for the drop
    3. purchase  buy with the best tool that is always available: curl_cffi with a perfect Chrome handshake and no
                 JavaScript (a stealth browser is the W2 Ch9 lab's territory, and a bonus here)

Against the full stack (level 7) each stage is answered by a different layer, and which layer answered is the
point: the table printed at the end is the kill chain you write up in the post-incident report. The number that
matters is stages that got through (0). A stage that gets through anywhere is a layer that is missing or silent.

    python attacks/round4_integrated.py
"""

import time

from _api import DROP, SKUS, Bot, Cost, emit, got_data, rng_for, say, verdict
from defenses import layers


def recon(rng):
    bot = Bot("bot:round4_recon", rng)
    aliases = " ".join(f'p{i}: product(sku: "{SKUS[0]}") {{ sku name price }}' for i in range(100))
    r = bot.post("/graphql", json=[{"query": "{ " + aliases + " }"}])
    res = verdict(r)
    if r.status_code == 200 and got_data(r):
        res.update(status="reserved")
    return res


def evade(rng, n=14, interval_s=0.35):
    bot = Bot("bot:round4_evade", rng)
    refused, last = None, None
    for _ in range(n):
        last = bot.get(DROP)
        if last.status_code != 200 and refused is None:
            refused = verdict(last)
        time.sleep(interval_s)
    return refused or dict(verdict(last), status="reserved")


def purchase(rng):
    """A bare HTTP purchase: no page script, so no sensor report. Stopped at the buy."""
    bot = Bot("bot:round4_purchase", rng)
    bot.get(DROP)
    r = bot.post("/api/buy", json={"sku": "lab-runner-9", "size": "10", "email": f"scalper{rng.randint(100, 9999)}@mail.example"})
    res = verdict(r)
    res["status"] = "reserved" if r.status_code == 201 else res["status"]
    return res


STAGES = {"recon": recon, "evade": evade, "purchase": purchase}


if __name__ == "__main__":
    print("=== Round 4: recon -> evade -> purchase ===")
    results = []
    with Cost() as cost:
        for name, fn in STAGES.items():
            res = fn(rng_for(f"round4-{name}"))
            res["stage"] = name
            res["layers"] = sorted({layers.layer_of(s) for s in res["signals"]})
            results.append(res)
    print(f"\n  {'stage':<10} {'result':<12} {'first layer':<12} signals")
    for res in results:
        say(res["stage"], res, "")
    print("\n  kill chain: " + " -> ".join(f"{r['stage']} stopped by {'/'.join(r['layers']) or 'nobody'}" for r in results))
    emit("round4_integrated", results, cost, kill_chain={r["stage"]: r["layers"] for r in results})
