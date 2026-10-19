"""
Chapter 7, Round 3 attack: the naive catalog crawler.

Objective: copy the whole catalog (names and prices) for a price-monitoring competitor. The crawler does
what cheap scrapers do:

  - breadth-first over every href in the raw HTML, robots.txt ignored
  - mines the site's JavaScript files for anything that looks like an API path
  - walks one SKU past the end of the catalog (p121..p125), in case some are not linked
  - tries a couple of "juicy" paths (/.env, /wp-admin/) while it is there

    python attacks/round3_crawler.py

Expected:   level 0-2: 120 products, nothing trapped.
            level 3+: trapped on the first page (the hidden link), then again on the honey SKU, the
            export URL from traps.js and the decoys. It still gets the catalog at level 3: detection is
            not prevention. It also takes home a product that does not exist, which is a canary.
"""

import json
import os
import re
import sys
from collections import deque
from urllib.parse import urljoin, urlparse

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tools"))
import trapkit  # noqa: E402  (labclient runs the localhost guard on import)
from trapkit import BASE_URL, LabClient, world_pool  # noqa: E402

ACTOR = "bot:r3_crawler"
MAX_PAGES = 200
CATALOG = 120
HREF = re.compile(r'href="([^"#]+)"')
SCRIPT = re.compile(r'<script[^>]+src="([^"]+)"')
JS_PATH = re.compile(r'["\'](/api/[^"\'\s]+)')
PRODUCT = re.compile(r"^/product/(p\d{3})$")
PROBES = ["/.env", "/wp-admin/"]


def run(verbose=False):
    bot = LabClient(ACTOR, ip=world_pool("cloud_vm")[4])
    hdrs = [("User-Agent", "catalog-sync/2.1")]
    products, fetched = {}, []

    def get(path):
        r = bot.get(path, hdrs)
        fetched.append((path, r.status_code))
        return r

    queue, seen = deque(["/"]), {"/"}
    while queue and len(fetched) < MAX_PAGES:
        path = queue.popleft()
        r = get(path)
        if r.status_code != 200:
            continue
        links = JS_PATH.findall(r.text) if path.endswith(".js") else HREF.findall(r.text) + SCRIPT.findall(r.text)
        for link in links:
            url = urlparse(urljoin("/", link))
            target = url.path + (f"?{url.query}" if url.query else "")
            if url.netloc or target in seen or url.path.startswith(("/logout", "/img/")):
                continue
            seen.add(target)
            queue.append(target)
        m = PRODUCT.match(path)
        if m:
            name = re.search(r"<h1>([^<]+)</h1>", r.text)
            price = re.search(r'class="price big">\$([\d.]+)', r.text)
            if name and price:
                products[m.group(1)] = (name.group(1), price.group(1))

    for n in range(CATALOG + 1, CATALOG + 6):                    # one SKU past the end, and a few more
        r = get(f"/product/p{n:03d}")
        m = re.search(r"<h1>([^<]+)</h1>", r.text) if r.status_code == 200 else None
        price = re.search(r'class="price big">\$([\d.]+)', r.text) if m else None
        if m and price:
            products[f"p{n:03d}"] = (m.group(1), price.group(1))
    for path in PROBES:
        get(path)

    scraped = [s for s in products if int(s[1:]) <= CATALOG]
    extra = sorted(s for s in products if int(s[1:]) > CATALOG)
    if verbose:
        print(f"Fetched {len(fetched)} URLs. The ones that are not catalog pages:")
        archive = [p for p, _ in fetched if p.startswith("/catalog/archive")]
        for path, status in fetched:
            if path.startswith("/catalog/archive"):
                if path == archive[0]:
                    print(f"  {status}  {path}   (and {len(archive) - 1} more archive pages: each links to three more)")
            elif not (PRODUCT.match(path) or path.startswith(("/products", "/static", "/search"))) and path != "/":
                print(f"  {status}  {path}")
        print(f"\nScraped {len(scraped)}/{CATALOG} catalog products, plus {len(extra)} that are not in any listing:")
        for sku in extra:
            print(f"  {sku}  {products[sku][0]:<30} ${products[sku][1]}")
    return {"attempted": CATALOG, "succeeded": len(scraped), "requests": len(fetched), "unlisted": extra}


if __name__ == "__main__":
    print("=== Round 3: naive crawler ===")
    print(json.dumps(run(verbose=True)))
