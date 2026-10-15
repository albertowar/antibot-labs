"""Round 3 attack: rent a box on infrastructure the operator vouches for.

Google documents that its user-triggered fetchers may come from App Engine egress, with reverse DNS
under *.gae.googleusercontent.com, and lists those prefixes in user-triggered-fetchers.json. Any
App Engine tenant can send any request with any User-Agent from those addresses. So the attacker
deploys the scraper there (an address in the lab's shared "App Engine" slice of the cloud_vm pool),
sets the User-Agent to Google-Read-Aloud, and passes forward-confirmed reverse DNS honestly: the
PTR really is 203-0-113-56.gae.googleusercontent.com and it really resolves back.

A second try claims GPTBot from the attacker's own hosting box, to show what a published range
check does for operators without reverse DNS.

Expected: L2 -> the squat takes the whole catalogue (FCrDNS passes, naive entitlement). L3 -> both
held ("shared infrastructure: network proven, program not"; "not in openai/gptbot.json").

    python attacks/round3_range_squat.py
"""

from __future__ import annotations

from _common import SQUAT_INDEX, SQUAT_POOL, UA, attacker_ip, catalog_paths, finish, report, scrape, world_pool


def run() -> dict:
    paths = catalog_paths()
    gptbot = scrape("gptbot-claim", attacker_ip("gptbot_claim"), UA["GPTBot"], paths)
    squat = scrape("shared-squat", world_pool(SQUAT_POOL)[SQUAT_INDEX], UA["Google-Read-Aloud"], paths)
    return {**squat, "gptbot_claim": gptbot}


if __name__ == "__main__":
    print("=== Round 3: claim GPTBot from our box; then squat on shared cloud egress as a Google fetcher ===")
    out = run()
    report("GPTBot from the hosting box  ", out["gptbot_claim"])
    report("Google-Read-Aloud from GAE   ", out)
    finish(out)
