"""Round 4 "attack": a verified crawler that pays.

Monetization is the one rung where the crawler getting through is the point.
LabTrainBot signs every request (Web Bot Auth, Ed25519), reads the RSL licence
to learn the price, and negotiates the pay-per-crawl exchange:

  --mode reactive   (default)  GET -> 402 + crawler-price -> retry with crawler-exact-price
  --mode proactive             GET with crawler-max-price -> 200 + crawler-charged

It keeps a running bill. The store's ledger must match it to the cent; if they
differ, one side is lying. Also try --max 0.005: a crawler whose budget is
below your price simply walks away, which is what most 402s meet in practice.

    python attacks/round4_paying_crawler.py [--mode proactive] [--max 0.05]
"""

from __future__ import annotations

import argparse
import re

from _common import (BASE_URL, TRAINBOT_RANGE, TRAINBOT_UA, Crawler, print_report, require_local,
                     trainbot_signer)


def run(base=BASE_URL, budget=700, mode="reactive", max_price=0.05):
    require_local(base)
    c = Crawler(base, TRAINBOT_UA, TRAINBOT_RANGE, budget=budget, obey_robots=True, robots_token="LabTrainBot", purpose="ai-train",
                follow_hidden=False, signer=trainbot_signer(),
                pay={"mode": mode, "max": max_price}, label=f"paying LabTrainBot ({mode})")
    robots = c.read_robots()
    lic = re.search(r"^License: (.*)$", robots, re.M)
    if lic:
        r = c.client.get(lic.group(1), headers={"User-Agent": TRAINBOT_UA, "X-Lab-Actor": "bot"})
        pay = re.search(r'<payment type="(\w+)">\s*<amount currency="(\w+)">([\d.]+)</amount>', r.text)
        print("RSL licence:", f"{pay.group(1)} {pay.group(2)} {pay.group(3)} per request" if pay
              else "no priced licence")
    rep = c.crawl()
    print_report(rep)
    return rep


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default=BASE_URL)
    ap.add_argument("--mode", choices=["reactive", "proactive"], default="reactive")
    ap.add_argument("--max", type=float, default=0.05, help="max USD per request the crawler will pay")
    a = ap.parse_args()
    run(a.url, mode=a.mode, max_price=a.max)
