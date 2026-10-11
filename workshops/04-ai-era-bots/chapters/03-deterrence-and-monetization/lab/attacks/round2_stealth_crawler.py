"""Round 2 attack: the stealth pivot.

Round 2 refuses every declared crawler it cannot verify, and every verified one
whose purpose is denied. The crawler's cheapest answer is to stop declaring
anything: a current Chrome User-Agent, a rotating pool of residential egress
IPs, no robots.txt request at all. This is the pattern Cloudflare documented
for Perplexity in August 2025 (declared crawler blocked -> undeclared traffic
posing as Chrome on macOS from unpublished ASNs).

Nothing in an identity-keyed policy can name this client. It gets 100% at
Level 2. That is the honest limit of Rounds 1-2 and the reason Round 3 exists.

    python attacks/round2_stealth_crawler.py
"""

from __future__ import annotations

import sys

from _common import BASE_URL, CHROME_UA, RESIDENTIAL, Crawler, print_report, require_local

POOL = RESIDENTIAL[:24]   # a small rented pool; real ones are far larger (see the content doc)


def run(base=BASE_URL, budget=400, label="stealth crawler"):
    require_local(base)
    c = Crawler(base, CHROME_UA, POOL, budget=budget, obey_robots=False,
                follow_hidden=True, label=label)
    rep = c.crawl()
    print_report(rep)
    return rep


if __name__ == "__main__":
    run(sys.argv[1] if len(sys.argv) > 1 else BASE_URL)
