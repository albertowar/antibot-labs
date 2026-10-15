"""Round 3 attack, step 1: the SAME stealth crawler, now against the maze.

Not one line of the bot changed since Round 2. It still follows every <a href> it sees, including
the one hidden link on every page. Watch where its budget goes: the maze multiplies links
twenty-fold per page, each decoy page tags the address that fetched it, and tagged addresses get
decoys instead of the catalogue.

    python attacks/round3_stealth_crawler.py
"""

from __future__ import annotations

from round2_stealth_crawler import run as _run


def run(budget=300):
    return _run(budget=budget, label="stealth crawler (unchanged)", name="naive")


if __name__ == "__main__":
    rep = run()
    print(f"\n{rep['maze_pages'] / max(1, rep['requests']):.0%} of the crawl budget went to decoy pages.")
