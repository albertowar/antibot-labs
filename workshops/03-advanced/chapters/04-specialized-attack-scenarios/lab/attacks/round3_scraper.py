"""
Round 3 attack: a competitor scraping the catalogue.

The economy: harvest the whole assortment, prices and stock, on a schedule. The scraper is a crawler
with stealth: a real Chrome's headers, a new residential address on every request (world.json's
`residential_proxy_net`), one cookie jar. It reads the listing pages, collects every product link in the
HTML, and fetches each product page. Headers and addresses are free to forge; what it cannot hide is that
it wants COVERAGE.

    python attacks/round3_scraper.py                 # follows every <a href>, including the one nobody can see
    python attacks/round3_scraper.py --skip-hidden   # renders like a browser: skips links a person cannot see

The first walks into the honeypot SKU. The second is the arms race: it avoids the trap and is cut off by
the coverage ceiling instead. It reports the per-session canary it found in the HTML (attribution).
"""

import argparse
import re

from _common import BASE_URL, LabClient, browser_headers, report, world_pool

ACTOR = "bot:scraper"
LISTING_PAGES = 5
ANCHOR = re.compile(r'<a\b[^>]*href="/product/([\w-]+)"[^>]*>')
CANARY = re.compile(r'data-canary="([0-9a-f]+)"')


def run(skip_hidden=False):
    bot = LabClient(ACTOR, pool=world_pool("residential_proxy_net"))
    queue, canary, listings_ok = [], "", 0
    for page in range(1, LISTING_PAGES + 1):
        r = bot.get(f"/products?page={page}", browser_headers("link", BASE_URL + "/"))
        if r.status_code != 200:
            continue
        listings_ok += 1
        canary = (CANARY.search(r.text) or [None, canary])[1]
        for tag in ANCHOR.finditer(r.text):
            invisible = 'aria-hidden="true"' in tag.group(0) or 'tabindex="-1"' in tag.group(0)
            if skip_hidden and invisible:
                continue
            if tag.group(1) not in queue:
                queue.append(tag.group(1))
    harvested, first_stop = 0, None
    for sku in queue:
        r = bot.get(f"/product/{sku}", browser_headers("link", BASE_URL + "/products"))
        if r.status_code == 200:
            harvested += 1
        elif first_stop is None:
            first_stop = (sku, r.headers.get("X-Lab-Signals", ""))
    return {"attacker": ACTOR, "attempted": len(queue), "succeeded": harvested, "pages_harvested": harvested,
            "listing_pages": listings_ok, "first_stop": first_stop, "canary": canary, "skip_hidden": skip_hidden}


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--skip-hidden", action="store_true")
    out = run(ap.parse_args().skip_hidden)
    print(f"[scraper] {out['listing_pages']} listing pages + {out['pages_harvested']} of {out['attempted']} product pages harvested; "
          f"first stopped at {out['first_stop']}; canary in the HTML: {out['canary']}")
    report(**out)
