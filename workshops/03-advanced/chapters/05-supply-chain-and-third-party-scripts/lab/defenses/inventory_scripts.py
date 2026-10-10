"""
inventory_scripts.py — DEFENSE (Round 1): know every script that runs.

Loads each page in a real browser (Playwright) and records every JavaScript
file the page pulls in — first-party and third-party alike. A store that
self-hosts its vendor files (as this one does, and as many do for privacy)
still needs this: the compromise shows up as a NEW file or a CHANGED file, not
as a new domain.

PCI DSS v4.0 req 6.4.3 makes this inventory mandatory on payment pages, so
treat /checkout as the page that matters most.

Fix vs. the naive version: the request handler is removed by its own reference,
not by poking at page.listeners(), which Playwright-Python does not expose.

Prereqs:  pip install playwright && playwright install chromium
Usage:    python inventory_scripts.py            # writes script_inventory.json
          python inventory_scripts.py --base http://127.0.0.1:5000
"""

import argparse
import asyncio
import json
import os
from urllib.parse import urlparse

from playwright.async_api import async_playwright

DEFAULT_BASE = os.environ.get("DEMO_URL", "http://127.0.0.1:5000")
PAGES = ["/", "/product/sku-sneaker", "/checkout", "/login"]
OUT = os.path.join(os.path.dirname(__file__), "script_inventory.json")


async def crawl_page(page, base: str, path: str) -> list:
    """Record every script URL the page loads. Returns a list of dicts."""
    scripts: list = []
    base_netloc = urlparse(base).netloc

    def on_request(req):
        if req.resource_type == "script":
            netloc = urlparse(req.url).netloc
            scripts.append({
                "url": req.url,
                "third_party": bool(netloc) and netloc != base_netloc,
            })

    page.on("request", on_request)
    try:
        await page.goto(base + path, wait_until="networkidle", timeout=15000)
    finally:
        page.remove_listener("request", on_request)   # remove by reference
    return scripts


async def build_inventory(base: str) -> dict:
    inventory = {}
    async with async_playwright() as p:
        browser = await p.chromium.launch()
        page = await browser.new_page()
        for path in PAGES:
            print(f"Crawling {base}{path} ...")
            found = await crawl_page(page, base, path)
            inventory[path] = found
            print(f"  {len(found)} script(s)")
        await browser.close()
    return inventory


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("--base", default=DEFAULT_BASE)
    args = ap.parse_args()

    inventory = asyncio.run(build_inventory(args.base))
    with open(OUT, "w") as fh:
        json.dump(inventory, fh, indent=2)
    total = sum(len(v) for v in inventory.values())
    print(f"\nWrote {OUT} ({total} script loads across {len(inventory)} pages)")


if __name__ == "__main__":
    main()
