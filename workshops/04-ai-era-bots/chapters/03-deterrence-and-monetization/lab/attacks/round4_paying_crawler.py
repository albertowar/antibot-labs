"""Round 4 "attack": a verified crawler that pays.

Monetization is the one rung where the crawler getting through is the point. LabTrainBot signs every
request (Web Bot Auth, Ed25519, the key directory its operator publishes), reads the RSL licence to
learn the price, and negotiates the pay-per-crawl exchange:

  --mode reactive   (default)  GET -> 402 + crawler-price -> retry with crawler-exact-price
  --mode proactive             GET with crawler-max-price -> 200 + crawler-charged

It keeps a running bill. The store's ledger (GET /lab/crawl/stats) must match it to the cent; if they
differ, one side is lying. Also try --max 0.005: a crawler whose budget is below your price simply
walks away, which is what most 402s meet in practice.

    python attacks/round4_paying_crawler.py [--mode proactive] [--max 0.05]
"""

from __future__ import annotations

import argparse
import re

from _common import BASE_URL, PAYING_RANGE, TRAINBOT_UA, Crawler, finish, trainbot_signer


def run(budget=700, mode="reactive", max_price=0.05):
    c = Crawler("paying", TRAINBOT_UA, PAYING_RANGE, budget=budget, obey_robots=True,
                robots_token="LabTrainBot", purpose="ai-train", follow_hidden=False, signer=trainbot_signer(),
                pay={"mode": mode, "max": max_price}, label=f"paying LabTrainBot ({mode})")
    robots = c.read_robots()
    lic = re.search(r"^License: (.*)$", robots, re.M)
    if lic:
        r = c._get(lic.group(1).replace(BASE_URL, ""))
        pay = re.search(r'<payment type="(\w+)">\s*<amount currency="(\w+)">([\d.]+)</amount>', r.text)
        print("RSL licence:", f"{pay.group(1)} {pay.group(2)} {pay.group(3)} per request" if pay
              else "no priced licence")
    return finish(c.crawl())


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["reactive", "proactive"], default="reactive")
    ap.add_argument("--max", type=float, default=0.05, help="max USD per request the crawler will pay")
    a = ap.parse_args()
    run(mode=a.mode, max_price=a.max)
