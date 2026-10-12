"""
Chapter 7 — Round 3 Attack, part b: The Polite Crawler (Section 7.5)

Objective: the same catalog, without stepping on anything. The crawler:

  - reads robots.txt and obeys it. Your trap paths are in there, so it
    avoids every one of them. That is the price of protecting good crawlers.
  - renders each page in Chromium and follows only links a human could see
    and click (`a:visible`)
  - never guesses ids: if the UI doesn't link it, the crawler doesn't fetch it

Expected results:
  - every level: 12/12 products, zero trap hits. Crawl traps have nothing to
    say about a client that only does what a person would do.

Setup (once):
    playwright install chromium
Run the demo site first:
    cd demo_site && DEFENSE_LEVEL=3 python app.py
Then run:
    python attacks/round3b_polite_crawler.py
"""

from collections import deque
from urllib.parse import urlparse
from urllib.robotparser import RobotFileParser

from playwright.sync_api import sync_playwright

from _lab import BASE_URL, lab_headers, require_local

ACTOR, IP = "round3b_polite_crawler", "203.0.113.14"
MAX_DEPTH = 2
UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36"


def run(verbose=False):
    require_local()
    products, visited = {}, []
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(user_agent=UA, extra_http_headers=lab_headers(ACTOR, IP))
        robots = RobotFileParser()
        robots.parse(context.request.get(f"{BASE_URL}/robots.txt").text().splitlines())
        page = context.new_page()

        queue, seen = deque([("/", 0)]), {"/"}
        while queue:
            path, depth = queue.popleft()
            page.goto(f"{BASE_URL}{path}")
            visited.append(path)
            if path.startswith("/products/"):
                products[int(path.rsplit("/", 1)[1])] = (
                    page.inner_text("#product-name"), page.inner_text("#product-price"))
            if depth == MAX_DEPTH:
                continue
            for href in page.locator("a:visible").evaluate_all("els => els.map(e => e.href)"):
                url = urlparse(href)
                if url.netloc != urlparse(BASE_URL).netloc or url.path in seen:
                    continue
                if url.path.startswith(("/trap-", "/lab/")):
                    continue                        # the lab's debug pages, not the store
                if not robots.can_fetch(UA, href):
                    if verbose:
                        print(f"  robots.txt says no: {url.path}")
                    continue
                seen.add(url.path)
                queue.append((url.path, depth + 1))
        browser.close()

    if verbose:
        print(f"Visited {len(visited)} pages, scraped {len(products)} products:")
        for pid, (name, price) in sorted(products.items()):
            print(f"  {pid:>3}  {name:<30} {price}")
    return {"actor": ACTOR, "requests": len(visited), "products": sorted(products)}


if __name__ == "__main__":
    print("=== Round 3b: polite, rendering crawler ===")
    run(verbose=True)
