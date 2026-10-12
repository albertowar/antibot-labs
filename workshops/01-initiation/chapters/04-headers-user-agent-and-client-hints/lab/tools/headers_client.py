"""
Chapter 4 helpers for the attack scripts: a scraper on a rented cloud address, what it wants (the
catalog, five pages of /api/products), and a tally that every script ends with.

Importing this module imports `labclient` (and through it the `labnet` guard), so every attack that uses it runs the localhost guard.

A header list is an ordered list of (name, value) pairs. `LabClient` sends it exactly as given, with no
library defaults added, so what you write is what the store's header checks see, in your order.
"""

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

from labclient import BASE_URL, LabClient, world_pool  # noqa: E402,F401

CATALOG_PAGES = 5                        # 120 products, 24 per page
CHROME_MAJOR = 153                       # bump with the Playwright pin (Chromium 153 for Playwright 1.63)
CHROME_UA = (f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
             f"Chrome/{CHROME_MAJOR}.0.0.0 Safari/537.36")


def bot(name, index=0):
    """A scraper client on a rented cloud address (203.0.113.0/26). Header checks ignore the address; IP
    reputation (Chapter 3) would not."""
    return LabClient(f"bot:{name}", ip=world_pool("cloud_vm")[index])


def requests_defaults():
    """What python-requests really sends, in its order: User-Agent, Accept-Encoding, Accept, Connection."""
    import requests
    return list(requests.utils.default_headers().items())


class Tally:
    """What one attack achieved: catalog pages fetched, products seen, and what the store said about the rest."""

    def __init__(self, name):
        self.name, self.attempted, self.succeeded, self.products = name, 0, 0, 0
        self.statuses, self.signals, self.score, self.notes = [], [], 0, []

    def page(self, status, signals="", score=0, products=0):
        self.attempted += 1
        self.statuses.append(status)
        if status == 200:
            self.succeeded += 1
            self.products += products
        else:
            for s in filter(None, (signals or "").split(",")):
                if s not in self.signals:
                    self.signals.append(s)
            self.score = max(self.score, int(score or 0))

    def note(self, text):
        if text not in self.notes:
            self.notes.append(text)

    def result(self):
        return {"name": self.name, "attempted": self.attempted, "succeeded": self.succeeded, "products": self.products,
                "statuses": self.statuses, "signals": self.signals, "score": self.score, "notes": self.notes}


def fetch_catalog(client, headers, tally, pages=CATALOG_PAGES):
    """Scrape /api/products page by page with `headers` (a list, or a callable(page) -> list)."""
    for page in range(1, pages + 1):
        h = headers(page) if callable(headers) else headers
        r = client.get(f"/api/products?page={page}", h)
        items = r.json().get("items", []) if r.status_code == 200 else []
        tally.page(r.status_code, r.headers.get("X-Lab-Signals", ""), r.headers.get("X-Lab-Score", 0), len(items))
    return tally


def report(result):
    ok = result["succeeded"]
    print(f"  Catalog pages: {ok}/{result['attempted']} ({result['products']} products)  statuses={sorted(set(result['statuses']))}")
    if ok < result["attempted"]:
        print(f"  Stopped with score {result['score']}: {', '.join(result['signals']) or 'no signals'}")
    for n in result["notes"]:
        print(f"    - {n}")


def finish(result):
    """Print the human report, then the one JSON line checkpoint.py reads."""
    report(result)
    print(json.dumps(result))
