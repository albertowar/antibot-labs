"""Round 4 attack: the free-path leak.

Same verified, honest LabTrainBot, but it reads the site the way a crawler engineer does: the
sitemap lists every product URL, the JSON API serves the catalogue 24 records a page (and the bulk
feed all of it at once), the feed lists the newest, and the search box returns a page of matches per
term. If the paywall was wired on the HTML pages only, all of that is free.

It never lies and never pays. With PAID_PATHS covering only /products and /product/ it rebuilds the
catalogue at $0.00. After TODO 2, every carrier returns 402 and, being honest and unwilling to pay
here, it leaves.

    python attacks/round4_free_path_leak.py
"""

from __future__ import annotations

import string

from _common import LEAK_RANGE, TRAINBOT_UA, Crawler, finish, trainbot_signer


def run(budget=120):
    c = Crawler("leak", TRAINBOT_UA, LEAK_RANGE, budget=budget, obey_robots=False,
                follow_hidden=False, signer=trainbot_signer(), label="free-path leak")
    seeds = ["/sitemap.xml", "/feed.xml", "/api/products.json"] + [f"/api/products?page={n}" for n in range(1, 6)] + \
            [f"/api/search?q={ch}" for ch in string.ascii_lowercase[:8]] + \
            [f"/search?q={ch}" for ch in string.ascii_lowercase[:8]]
    for s in seeds:
        if c.stats["requests"] >= budget:
            break
        r = c.fetch(s)
        if r.status_code == 200:
            c.absorb(s, r)
    return finish(c.report())


if __name__ == "__main__":
    rep = run()
    print(f"\nRebuilt {rep['coverage']:.0%} of the catalogue for ${rep['spent_usd']:.2f} without touching a "
          f"priced page." if rep["coverage"] > 0.05 else "\nEvery carrier is priced now; the honest crawler left with nothing.")
