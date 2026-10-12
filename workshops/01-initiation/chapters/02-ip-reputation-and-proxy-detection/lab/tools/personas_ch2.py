"""
Chapter 2 shoppers: the starter's 40 shoppers, in a hurry.

The Chapter 2 rounds run next to a scraper that finishes in seconds. With the starter's
browse pacing (about 11 s of reading per shopper, 8 at a time) the six phones that share
one carrier-NAT address spread their requests over more than a minute, and no per-IP limit
a real site would set ever notices them. Real CGNAT addresses carry thousands of people,
so the lab compresses time instead: `rush` is the same journey (land, catalog, product,
cart, checkout) with every pause cut to a fifth.

    python tools/population.py --scenario rush     # registered when tools/personas_*.py load
"""

import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import population  # noqa: E402
from labclient import BASE_URL, form_fields, product_skus  # noqa: E402

SPEEDUP = 5.0


def _pause(rng, lo, hi):
    time.sleep(rng.uniform(lo, hi) / SPEEDUP)


def scenario_rush(p, client, rng):
    _visit, _post, _stop = population._visit, population._post, population._stop
    _pause(rng, 0, 2)
    r = _visit(p, client, "/", "typed")
    if r.status_code != 200:
        return _stop(p, client, "blocked", r)
    _pause(rng, 0.5, 2.0)
    r = _visit(p, client, "/products?category=" + rng.choice(["shoes", "packs", "jackets"]), "link", BASE_URL + "/")
    if r.status_code != 200:
        return _stop(p, client, "blocked", r)
    skus = product_skus(r.text)
    if not skus:
        return _stop(p, client, "error", r)
    sku = rng.choice(skus)
    _pause(rng, 0.5, 1.5)
    r = _visit(p, client, f"/product/{sku}", "link", BASE_URL + "/products")
    if r.status_code != 200:
        return _stop(p, client, "blocked", r)
    fields = form_fields(r.text)
    _pause(rng, *p.fill)
    r = _post(p, client, "/cart/add", {"csrf": fields.get("csrf", ""), "sku": sku, "size": fields.get("size", ""), "qty": "1",
                                       "next": "/cart"}, BASE_URL + f"/product/{sku}")
    if r.status_code >= 400:
        return _stop(p, client, "blocked", r)
    r = _visit(p, client, "/checkout", "link", BASE_URL + "/cart")
    if r.status_code != 200:
        return _stop(p, client, "blocked", r)
    fields = form_fields(r.text)
    _pause(rng, *p.fill)
    data = {"csrf": fields.get("csrf", ""), "email": f"{p.actor.replace(':', '.')}@example.test", "name": "Pat Shopper",
            "address": "1 Trail Way", "city": "Boulder", "postcode": "80301", "card": "4242424242424242", "exp": "12/29", "cvc": "123"}
    r = _post(p, client, "/checkout", data, BASE_URL + "/checkout", ip=p.checkout_ip)
    if r.status_code == 200 and "order-confirmed" in r.text:
        return _stop(p, client, "bought", r)
    return _stop(p, client, "blocked" if r.status_code in (403, 429) else "failed", r)


population.SCENARIOS["rush"] = scenario_rush
