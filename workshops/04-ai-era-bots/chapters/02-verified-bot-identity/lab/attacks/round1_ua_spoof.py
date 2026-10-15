"""Round 1 attack: say you are Googlebot.

The store's crawler gate at DEFENSE_LEVEL=0 trusts the User-Agent. A scraper that would be held
to 30 requests a minute sets one header and gets the crawler's 600. This is not exotic: HUMAN
measured 5.7% of requests presenting an AI-crawler User-Agent as spoofed (2025), and fake
Googlebots have been a staple of scraping for twenty years.

The script runs the honest scraper first, then the same scraper claiming to be Googlebot, from a
second rented hosting address so the two have separate budgets.

Expected: L0 -> honest ~30 pages, spoof every page in the verified lane. L1+ -> the spoof is held
to the anonymous lane (the PTR of its address is static-203-0-113-66.attacker-hosting.example,
not under googlebot.com).

    python attacks/round1_ua_spoof.py
"""

from __future__ import annotations

from _common import UA, attacker_ip, catalog_paths, finish, report, scrape


def run() -> dict:
    paths = catalog_paths()
    honest = scrape("honest-scraper", attacker_ip("honest"), UA["scraper"], paths)
    spoof = scrape("ua-spoof", attacker_ip("ua_spoof"), UA["Googlebot"], paths)
    return {**spoof, "honest": honest}


if __name__ == "__main__":
    print("=== Round 1: the honest scraper, then the same scraper claiming to be Googlebot ===")
    out = run()
    report("honest scraper ", out["honest"])
    report("UA = Googlebot ", out)
    finish(out)
