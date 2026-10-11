"""Round 3 attack, step 1: the SAME stealth crawler, now against the maze.

Not one line of the bot changed since Round 2. It still follows every <a href>
it sees, including the one hidden link on every page. Watch where its budget
goes: the maze multiplies links twenty-fold per page, each decoy page tags the
IP that fetched it, and tagged IPs get decoys instead of the catalogue.

    python attacks/round3_stealth_crawler.py
"""

from __future__ import annotations

import sys

from round2_stealth_crawler import run as _run
from _common import BASE_URL


def run(base=BASE_URL, budget=300):
    return _run(base, budget=budget, label="stealth crawler (unchanged)")


if __name__ == "__main__":
    rep = run(sys.argv[1] if len(sys.argv) > 1 else BASE_URL)
    share = rep["maze_pages"] / max(1, rep["requests"])
    print(f"\n{share:.0%} of the crawl budget went to decoy pages.")
