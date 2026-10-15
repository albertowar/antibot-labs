"""Round 1 attack (the other half): the same declared crawler, ignoring the policy.

Identical User-Agent to the compliant crawler, but it never requests robots.txt, ignores
Content-Usage headers, and crawls from a datacenter range its operator never published. This is the
common case in 2025-26 server logs: a declared token that violates the rules it claims to follow,
from addresses that are not the operator's (either a careless operator or someone borrowing the name).

At Level 1 every one of its requests is logged as a robots.txt violation
(`crawl_policy:robots_violation` in the decision log) and it still gets 100% of the catalogue. The
violation log is the signal Round 2 enforces on.

    python attacks/round1_ignoring_crawler.py
"""

from __future__ import annotations

from _common import DATACENTER, TRAINBOT_UA, Crawler, finish


def run(budget=400):
    c = Crawler("ignoring", TRAINBOT_UA, DATACENTER, budget=budget, obey_robots=False,
                follow_hidden=True, label="ignoring LabTrainBot")
    return finish(c.crawl())


if __name__ == "__main__":
    run()
