"""
Chapter 8, Round 3 attack, part b: the polite crawler.

Objective: the same catalog, without stepping on anything. The crawler:

  - reads robots.txt and obeys it (RFC 9309, longest match). Your trap paths are in there, so it
    avoids every one of them. That is the price of protecting good crawlers.
  - renders each page in Chromium and follows only links a human could see and click (`a:visible`)
  - never guesses SKUs: if the UI does not link it, the crawler does not fetch it

    python attacks/round3b_polite_crawler.py            # needs: python -m playwright install chromium

Expected:   every level: 120/120 products, zero trap hits. Crawl traps have nothing to say about a
            client that only does what a person would do. It never even sees the trap link: `a:visible`
            skips it before robots.txt is consulted.
"""

import json
import os
import sys
from collections import deque
from urllib.parse import urlparse

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tools"))
import trapkit  # noqa: E402  (labclient runs the localhost guard on import)
from trapkit import BASE_URL, world_pool  # noqa: E402
from labclient import browser_context  # noqa: E402

ACTOR = "bot:r3b_polite_crawler"
MAX_DEPTH = 2
CATALOG = 120


def run(verbose=False):
    from playwright.sync_api import sync_playwright
    products, visited = {}, []
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser_context(browser, ACTOR, world_pool("cloud_vm")[5])
        context.route("**/img/**", lambda route: route.abort())      # we only want the text
        robots = trapkit.Robots(context.request.get(f"{BASE_URL}/robots.txt").text())
        page = context.new_page()
        queue, seen = deque([("/", 0)]), {"/"}
        while queue:
            path, depth = queue.popleft()
            page.goto(f"{BASE_URL}{path}")
            visited.append(path)
            if path.startswith("/product/p"):
                products[path.rsplit("/", 1)[1]] = (page.inner_text(".pdp-info h1"), page.inner_text(".pdp-info .price"))
            if depth == MAX_DEPTH:
                continue
            for href in page.locator("a:visible").evaluate_all("els => els.map(e => e.href)"):
                url = urlparse(href)
                target = url.path + (f"?{url.query}" if url.query else "")
                if url.netloc != urlparse(BASE_URL).netloc or target in seen or url.path.startswith(("/logout", "/lab/", "/whoami")):
                    continue
                seen.add(target)
                if not robots.allowed(target):
                    if verbose:
                        print(f"  robots.txt says no: {target}")
                    continue
                queue.append((target, depth + 1))
        browser.close()
    scraped = [s for s in products if int(s[1:]) <= CATALOG]
    if verbose:
        print(f"Visited {len(visited)} pages, scraped {len(scraped)}/{CATALOG} products.")
    return {"attempted": CATALOG, "succeeded": len(scraped), "requests": len(visited)}


if __name__ == "__main__":
    print("=== Round 3b: polite, rendering crawler ===")
    print(json.dumps(run(verbose=True)))
