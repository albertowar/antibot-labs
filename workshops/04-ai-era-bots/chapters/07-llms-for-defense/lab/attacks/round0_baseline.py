"""
W4 Ch7 — Round 0 Attack: the bots you already know

Two scalper families from earlier workshops, running on cheap cloud servers:

  naive_scalper     httpx-style script: no assets, metronome pacing. Follows the
                    hidden honeypot link (W1 Ch7) and pokes the feed robots.txt
                    disallows.
  headless_scalper  automated Chrome (W2 Ch1) with the HeadlessChrome token still
                    in its User-Agent: loads assets, paces at ~1 s.

They carry no payload. They exist so the analyst (heuristic or LLM) has
something easy to be right about, and so the Round 1 injection has a baseline
to be compared with.

Run:
    python attacks/round0_baseline.py
"""

import os
import random
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tools"))

import personas_llm as pl  # noqa: E402  (imports labclient, which runs the labnet guard)
from labclient import world_pool  # noqa: E402

HEADLESS_UA = pl.UA["chrome_linux"].replace("Chrome/", "HeadlessChrome/")


def naive_scalper(rng):
    ip = rng.choice(world_pool("cloud_vm"))
    if rng.random() < 0.5:
        ua, langs = "python-httpx/0.28.1", ""
    else:  # borrowed Chrome UA, nothing else (W1 Ch4 Round 2)
        ua, langs = pl.UA["chrome_win"], ""
    return pl.Rec(cohort="naive_scalper", is_bot=True, ip=ip, ua=ua, langs=langs,
                  think=pl.fixed_think(1.0), browse=0, loads_assets=False,
                  honeypot=0.7, disallowed=0.3, usd_per_gb=0.10)


def headless_scalper(rng):
    ip = rng.choice(world_pool("cloud_vm"))
    return pl.Rec(cohort="headless_scalper", is_bot=True, ip=ip, ua=HEADLESS_UA,
                  langs=["en-US", "en"], think=pl.fixed_think(0.8), browse=rng.randint(0, 1),
                  loads_assets=True, honeypot=0.25, usd_per_gb=0.10)


def recs(n_each=40, seed=0):
    rng = random.Random(seed + 500)
    return [naive_scalper(rng) for _ in range(n_each)] + [headless_scalper(rng) for _ in range(n_each)]


def run(n_each=40, seed=11):
    return pl.run_bots(recs(n_each, seed), "round0_baseline", seed=seed, run="round0_baseline")


if __name__ == "__main__":
    results = run()
    for family in ("naive_scalper", "headless_scalper"):
        mine = [r for r in results if r["cohort"] == family]
        ok = sum(r["final"] == "confirmed" for r in mine)
        print(f"  {family:<18} checkouts succeeded: {ok}/{len(mine)}")
    print(pl.summary_line(results))
