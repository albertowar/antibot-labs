"""Round 3 attack, step 2: a maze-aware stealth crawler.

The counter to a tarpit is hygiene, and every serious crawler has it:

  * never follow links a human could not click (display:none, nofollow,
    aria-hidden, tabindex=-1)
  * read robots.txt — not to obey it, but as a list of trap hints: a path the
    site Disallows for everyone is either worthless or a trap
  * cap depth per path prefix, and bail on pages whose text repeats itself
    (a crude stand-in for the perplexity check real crawlers run)

It still declares nothing, still rotates residential IPs, still ignores the
policy. It never enters the maze, is never tagged, and gets the catalogue.
That is the limit of deterrence: it taxes the careless, not the careful. What
the careful crawler cannot avoid is the request volume and the breadth of its
crawl, which is where W2's behavioural and ML layers, and W3 Ch6's coverage
cap, pick up.

    python attacks/round3_maze_aware_crawler.py
"""

from __future__ import annotations

import sys

from _common import BASE_URL, CHROME_UA, RESIDENTIAL, Crawler, print_report, require_local
from round2_stealth_crawler import POOL


def run(base=BASE_URL, budget=300):
    require_local(base)
    c = Crawler(base, CHROME_UA, POOL, budget=budget, obey_robots=False,
                follow_hidden=False, trap_hints=True, max_depth=20, babble_limit=0.25,
                label="maze-aware stealth crawler")
    rep = c.crawl()
    print_report(rep)
    return rep


if __name__ == "__main__":
    run(sys.argv[1] if len(sys.argv) > 1 else BASE_URL)
