"""
Chapter 8 — Round 3 Attack: Naive Catalog Crawler (Section 8.5)

Objective: copy the whole catalog (names and prices) for a price-monitoring
competitor. The crawler does what cheap scrapers do:

  - breadth-first over every href in the raw HTML, robots.txt ignored
  - mines JavaScript files for anything that looks like an API path
  - enumerates /api/products/<id> from 1 to 20, in case some aren't linked
  - tries a couple of "juicy" paths (/.env, /wp-admin/) while it's there

Expected results:
  - level 0-2: 12 products, nothing trapped
  - level 3+: trapped on the first page (the hidden footer link), then again
    on the honey product (id 13), the export URL from store.js and the decoys.
    It still gets the catalog at level 3: detection is not prevention.
    It also takes home a product that doesn't exist, which is a canary.

Run the demo site first:
    cd demo_site && DEFENSE_LEVEL=3 python app.py
Then run:
    python attacks/round3_crawler.py
"""

import re
from collections import deque
from urllib.parse import urljoin, urlparse

from _lab import http_client

ACTOR, IP = "round3_crawler", "203.0.113.13"
MAX_PAGES = 40
HREF = re.compile(r'(?:href|src)="([^"#]+)"')
JS_PATH = re.compile(r'["\'](/api/[^"\'\s]+)')
PROBES = ["/.env", "/wp-admin/"]


def run(verbose=False):
    products, fetched = {}, []
    with http_client(ACTOR, IP, user_agent="catalog-sync/2.1") as client:
        queue, seen = deque(["/"]), {"/"}
        while queue and len(fetched) < MAX_PAGES:
            path = queue.popleft()
            response = client.get(path)
            fetched.append((path, response.status_code))
            text = response.text
            links = JS_PATH.findall(text) if path.endswith(".js") else HREF.findall(text)
            for link in links:
                url = urlparse(urljoin("/", link))
                target = url.path + (f"?{url.query}" if url.query else "")
                if url.netloc or target in seen:
                    continue
                seen.add(target)
                queue.append(target)
            m = re.search(r'id="product-name">([^<]+)<.*?id="product-price">\$([\d.]+)', text, re.S)
            if m and path.startswith("/products/"):
                products[int(path.rsplit("/", 1)[1])] = (m.group(1), m.group(2))

        for pid in range(1, 21):
            response = client.get(f"/api/products/{pid}")
            fetched.append((f"/api/products/{pid}", response.status_code))
            if response.status_code == 200:
                item = response.json()
                products[item["id"]] = (item["name"], item["price"])

        for path in PROBES:
            fetched.append((path, client.get(path).status_code))

    if verbose:
        print(f"Fetched {len(fetched)} URLs; the interesting ones:")
        for path, status in fetched:
            if not path.startswith(("/products/", "/api/products/")) or status != 200 \
                    or path.endswith("/13"):
                print(f"  {status}  {path}")
        print(f"\nScraped {len(products)} products:")
        for pid, (name, price) in sorted(products.items()):
            print(f"  {pid:>3}  {name:<30} {price}")
    return {"actor": ACTOR, "requests": len(fetched), "products": sorted(products)}


if __name__ == "__main__":
    print("=== Round 3: naive crawler ===")
    run(verbose=True)
