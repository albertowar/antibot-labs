"""
inventory_scripts.py: DEFENSE (Round 1). Know every script that runs on the payment pages.

Loads the slice's pages in a real browser (Playwright) and records every JavaScript file each page
pulls in, first-party and third-party alike. A store that self-hosts its vendor files (as this one
does, and as many do for privacy) still needs this: the compromise shows up as a NEW file or a
CHANGED file, not as a new domain.

PCI DSS v4.0 requirement 6.4.3 makes this inventory mandatory on payment pages, so the checkout page
is the one that matters most. The crawl must look like a customer: /checkout redirects to /cart when
the cart is empty, so it adds an item first.

Prereqs:  pip install -r requirements-browser.txt && python -m playwright install chromium
Usage:    python defenses/inventory_scripts.py            # writes instance/script_inventory.json
          python defenses/inventory_scripts.py --base http://127.0.0.1:5000
"""

import argparse
import asyncio
import json
import os
import sys
from urllib.parse import urlparse

from playwright.async_api import async_playwright

LAB = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
sys.path.insert(0, LAB)  # lab root: labnet.py
from labnet import target  # noqa: E402

DEFAULT_BASE = target("DEMO_URL", "http://127.0.0.1:5000")
PAGES = ["/", "/login", "/checkout"]          # the slice: the two forms a skimmer targets, and the home page
OUT = os.path.join(LAB, "instance", "script_inventory.json")


async def crawl_page(page, base: str, path: str) -> list:
    """Record every script URL the page loads. Returns a list of dicts."""
    scripts: list = []
    base_netloc = urlparse(base).netloc

    def on_request(req):
        if req.resource_type == "script":
            scripts.append({"url": req.url, "third_party": urlparse(req.url).netloc != base_netloc})

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
        await page.goto(base + "/product/p001", wait_until="networkidle", timeout=15000)
        async with page.expect_response(lambda r: r.request.method == "POST" and "/cart/add" in r.url, timeout=15000):
            await page.click("#add-to-cart")             # so /checkout renders the payment form
        await page.wait_for_load_state("load")
        for path in PAGES:
            found = await crawl_page(page, base, path)
            inventory[path] = found
            print(f"Crawled {base}{path}: {len(found)} script(s)")
        await browser.close()
    return inventory


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("--base", default=DEFAULT_BASE)
    args = ap.parse_args()
    target("DEMO_URL", args.base)                        # the guard, for a --base the student typed

    inventory = asyncio.run(build_inventory(args.base))
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w") as fh:
        json.dump(inventory, fh, indent=2)
    total = sum(len(v) for v in inventory.values())
    print(f"\nWrote {os.path.relpath(OUT, LAB)} ({total} script loads across {len(inventory)} pages)")


if __name__ == "__main__":
    main()
