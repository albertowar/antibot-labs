"""Round 3 attack: rent a box on infrastructure the operator vouches for.

Google documents that its user-triggered fetchers may come from App Engine
egress, with reverse DNS under *.gae.googleusercontent.com, and lists those
prefixes in user-triggered-fetchers.json. Any App Engine tenant can send any
request with any User-Agent from those addresses. So the attacker deploys the
scraper there (203.0.113.99 in the lab), sets the User-Agent to Google-Read-Aloud,
and passes forward-confirmed reverse DNS honestly: the PTR really is
203-0-113-99.gae.googleusercontent.com and it really resolves back.

A second try claims GPTBot from the attacker's own box, to show what a published
range check does for operators without reverse DNS.

Expected: L2 -> 200/200 (FCrDNS passes, naive entitlement). L3 -> 30/200
("shared infrastructure: network proven, program not"). GPTBot claim: 30/200 at L3.

    python attacks/round3_range_squat.py
"""

from __future__ import annotations

import httpx

from _common import ATTACKER_IP, BASE_URL, SQUAT_IP, UA_GPTBOT, UA_READ_ALOUD, headers, report, require_local_target, scrape_catalog


def run(base: str = BASE_URL) -> dict:
    require_local_target(base)
    with httpx.Client(base_url=base, timeout=10) as c:
        c.post("/admin/reset", params={"scope": "budgets"})   # a fresh minute, same caches
        gptbot = scrape_catalog(c, headers("bot-gptbot-claim", ATTACKER_IP, UA_GPTBOT))
        c.post("/admin/reset", params={"scope": "budgets"})
        squat = scrape_catalog(c, headers("bot-shared-squat", SQUAT_IP, UA_READ_ALOUD))
    return {"gptbot_claim": gptbot, "squat": squat, "scraped": squat["scraped"], "total": squat["total"]}


if __name__ == "__main__":
    print("=== Round 3: claim GPTBot from our box; then squat on shared cloud egress as a Google fetcher ===")
    out = run()
    report("GPTBot from 192.0.2.77     ", out["gptbot_claim"])
    report("Google-Read-Aloud from GAE ", out["squat"])
