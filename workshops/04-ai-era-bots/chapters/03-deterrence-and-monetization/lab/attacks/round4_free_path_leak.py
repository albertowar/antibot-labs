"""Round 4 attack: the free-path leak.

Same verified, honest LabTrainBot, but it reads the site the way a crawler
engineer does: the sitemap lists every product URL, the JSON API serves the
catalogue twenty records a page, and the search box returns fifty matches per
letter. If the paywall was wired on the HTML pages only, all of that is free.

It never lies and never pays. With PAID_PATHS covering only /catalog and
/product/ it rebuilds most of the catalogue at $0.00. After TODO 2, every
carrier returns 402 and, being honest and unwilling to pay here, it leaves.

    python attacks/round4_free_path_leak.py
"""

from __future__ import annotations

import string
import sys

from _common import (BASE_URL, TRAINBOT_RANGE, TRAINBOT_UA, Crawler, print_report, require_local,
                     trainbot_signer)


def run(base=BASE_URL, budget=120):
    require_local(base)
    c = Crawler(base, TRAINBOT_UA, TRAINBOT_RANGE, budget=budget, obey_robots=False,
                follow_hidden=False, signer=trainbot_signer(), label="free-path leak")
    seeds = ["/sitemap.xml"] + [f"/api/products.json?page={n}" for n in range(1, 16)] + \
            [f"/search?q={ch}" for ch in string.ascii_lowercase[:12]]
    for s in seeds:
        if c.stats["requests"] >= budget:
            break
        r = c.fetch(f"{base}{s}")
        ctype = r.headers.get("content-type", "")
        if r.status_code != 200:
            continue
        if "json" in ctype:
            c.skus.update(p["sku"] for p in r.json().get("products", []))
        else:
            from _common import SKU_RE
            c.skus.update(SKU_RE.findall(r.text))
    c.stats["seconds"] = 0
    rep = c.report()
    print_report(rep)
    return rep


if __name__ == "__main__":
    rep = run(sys.argv[1] if len(sys.argv) > 1 else BASE_URL)
    print(f"\nRebuilt {rep['coverage']:.0%} of the catalogue for ${rep['spent_usd']:.2f} "
          f"without touching a priced page." if rep["coverage"] > 0.05 else
          "\nEvery carrier is priced now; the honest crawler left with nothing.")
