"""
W4 Chapter 7 — Round 0 Attack: the bots you already know

Two scalper families from earlier workshops, running on cheap cloud servers:

  naive_scalper     httpx script: no assets, metronome pacing. Crawls every
                    link on the home page, including the hidden honeypot
                    link (W1 Ch8), and pokes the API robots.txt disallows.
  headless_scalper  automated Chrome (W2 Ch1) with the HeadlessChrome token
                    still in its User-Agent: loads assets, paces at ~1 s.

They carry no payload. They exist so the analyst (heuristic or LLM) has
something easy to be right about, and so the Round 1 injection has a
baseline to be compared with.

Run:
    python attacks/round0_baseline.py
"""

import os
import random
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))

import labnet  # noqa: E402
import shopper  # noqa: E402
from shopper import UA, Persona, browser_headers, fixed_think  # noqa: E402

HEADLESS_UA = UA["chrome_linux"].replace("Chrome/", "HeadlessChrome/")


def naive_scalper(rng):
    ip, _ = labnet.Pool("datacenter", rng=rng).next()
    if rng.random() < 0.5:
        ua, headers = "python-httpx/0.28.1", {}
    else:  # borrowed Chrome UA, nothing else (W1 Ch4 Round 2)
        ua, headers = UA["chrome_win"], {"Accept": "*/*"}
    return Persona(actor="round0_baseline", cohort="naive_scalper", is_bot=True, ip=ip,
                   user_agent=ua, headers=headers, think=fixed_think(1.0), browse=0,
                   loads_assets=False, honeypot=0.7, api_v0=0.3, usd_per_gb=0.10)


def headless_scalper(rng):
    ip, _ = labnet.Pool("datacenter", country="US", rng=rng).next()
    locale = shopper.LOCALES[1]  # America/New_York
    return Persona(actor="round0_baseline", cohort="headless_scalper", is_bot=True, ip=ip,
                   user_agent=HEADLESS_UA, headers=browser_headers(locale[1]),
                   think=fixed_think(0.8), browse=rng.randint(0, 1), loads_assets=True,
                   honeypot=0.25, usd_per_gb=0.10)


def personas(n_each=40, seed=0):
    rng = random.Random(seed + 500)
    return [naive_scalper(rng) for _ in range(n_each)] + [headless_scalper(rng) for _ in range(n_each)]


def run(n_each=20, seed=11):
    """Run the attack; return one result per session (used by tools/checkpoint.py)."""
    return shopper.run_sessions(personas(n_each, seed), seed=seed, run="round0_baseline")


if __name__ == "__main__":
    print(f"=== Round 0: baseline scalpers → {labnet.target()} ===")
    results = run()
    for family in ("naive_scalper", "headless_scalper"):
        mine = [r for r in results if r["cohort"] == family]
        ok = sum(shopper.succeeded(r) for r in mine)
        print(f"  {family:<18} checkouts succeeded: {ok}/{len(mine)}")
