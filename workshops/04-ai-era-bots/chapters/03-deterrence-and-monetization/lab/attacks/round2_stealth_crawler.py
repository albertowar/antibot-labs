"""Round 2 attack: the stealth pivot.

Round 2 refuses every declared crawler it cannot verify, and every verified one whose purpose is
denied. The crawler's cheapest answer is to stop declaring anything: a current Chrome User-Agent, a
rotating pool of residential egress addresses, no robots.txt request at all. This is the pattern
Cloudflare documented for Perplexity in August 2025 (declared crawler blocked -> undeclared traffic
posing as Chrome on macOS from unpublished ASNs).

Nothing in an identity-keyed policy can name this client. It gets 100% at Level 2. That is the honest
limit of Rounds 1-2 and the reason Round 3 exists.

    python attacks/round2_stealth_crawler.py
"""

from __future__ import annotations

from _common import CHROME_UA, STEALTH_POOL, Crawler, finish


def run(budget=400, label="stealth crawler", name="stealth"):
    c = Crawler(name, CHROME_UA, STEALTH_POOL, budget=budget, obey_robots=False,
                follow_hidden=True, label=label)
    return finish(c.crawl())


if __name__ == "__main__":
    run()
