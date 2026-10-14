"""
Chapter 2 shoppers: the starter's 40 shoppers, in a hurry, and signing in.

The rate-limit rounds run next to a scraper that finishes in seconds. With the starter's
browse pacing the six phones that share one carrier-NAT address spread their requests over
more than a minute, and no per-IP limit a real site would set ever notices them. Real CGNAT
addresses carry thousands of people, so the lab compresses time instead: `rush` is the same
journey with every pause cut to a fifth.

    rush        land, catalog, product, cart, checkout (Rounds 1-3, 5)
    rush_login  the rush, then a sign-in from the shopper's own account (Rounds 4-5)

`rush_login` is what shows the cost of the login limits: the CGNAT phones all sign in from
their two shared addresses, so a per-IP login bucket sized for one person throttles them, and
one shopper (human:autofill:00) fat-fingers the password twice before getting it right, which
a per-account cap must tolerate.

    python tools/population.py --scenario rush      # registered when tools/personas_*.py load
"""

import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import population  # noqa: E402
from labclient import BASE_URL, csrf_of, form_fields, product_skus  # noqa: E402

SPEEDUP = 5.0
TYPO_ACTOR = "human:autofill:00"        # this shopper mistypes twice, then succeeds


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
    r = _post(p, client, "/cart/add", {"csrf": fields.get("csrf", ""), "sku": sku, "size": fields.get("size", ""),
                                       "qty": "1", "next": "/cart"}, BASE_URL + f"/product/{sku}")
    if r.status_code >= 400:
        return _stop(p, client, "blocked", r)
    r = _visit(p, client, "/checkout", "link", BASE_URL + "/cart")
    if r.status_code != 200:
        return _stop(p, client, "blocked", r)
    fields = form_fields(r.text)
    _pause(rng, *p.fill)
    data = {"csrf": fields.get("csrf", ""), "email": f"{p.actor.replace(':', '.')}@example.test", "name": "Pat Shopper",
            "address": "1 Trail Way", "city": "Boulder", "postcode": "80301", "card": "4242424242424242",
            "exp": "12/29", "cvc": "123"}
    r = _post(p, client, "/checkout", data, BASE_URL + "/checkout", ip=p.checkout_ip)
    if r.status_code == 200 and "order-confirmed" in r.text:
        return _stop(p, client, "bought", r)
    return _stop(p, client, "blocked" if r.status_code in (403, 429) else "failed", r)


def scenario_rush_login(p, client, rng):
    """Browse like the rush, then sign in. CGNAT phones share an address; one shopper mistypes."""
    from demo_site.seed import password_for, username
    _visit, _post, _stop = population._visit, population._post, population._stop
    _pause(rng, 0, 2)
    r = _visit(p, client, "/", "typed")
    if r.status_code != 200:
        return _stop(p, client, "blocked", r)
    _pause(rng, 0.5, 1.5)
    r = _visit(p, client, "/products?category=" + rng.choice(["shoes", "packs", "jackets"]), "link", BASE_URL + "/")
    if r.status_code != 200:
        return _stop(p, client, "blocked", r)
    i = p.account if p.account is not None else 100
    r = _visit(p, client, "/login", "typed", BASE_URL + "/")
    if r.status_code != 200:
        return _stop(p, client, "blocked", r)
    attempts = []
    if p.actor == TYPO_ACTOR:
        attempts = [(username(i), "wrong-one"), (username(i), "wrong-two")]       # fat fingers, twice
    attempts.append((username(i), password_for(i)))
    last = None
    for email, pw in attempts:
        _pause(rng, *p.fill)
        last = _post(p, client, "/login", {"csrf": csrf_of(r.text), "email": email, "password": pw,
                                           "next": "/account"}, BASE_URL + "/login")
        if last.status_code in (403, 429):
            return _stop(p, client, "blocked", last)
    if last is not None and last.status_code in (302, 303):
        r = _visit(p, client, "/account", "link", BASE_URL + "/login")
        return _stop(p, client, "logged_in" if r.status_code == 200 else "blocked", r)
    return _stop(p, client, "failed", last)


population.SCENARIOS["rush"] = scenario_rush
population.SCENARIOS["rush_login"] = scenario_rush_login
