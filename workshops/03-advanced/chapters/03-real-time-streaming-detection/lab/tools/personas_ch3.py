"""
W3 Ch3's shoppers: the starter's 40 people, signing in the way the credential stuffers do.

The streaming detectors in this chapter watch the stream of requests, and the people who could be
caught by mistake are the ones whose stream looks a little like a campaign: they sign in, they
sometimes fail once, and eight of them share two carrier-NAT addresses. Every round runs them next
to the attack.

    scenario    what each person does
    ----------  ---------------------------------------------------------------------------------
    ch3_shop    land on the home page, look at the catalogue and two or three products (1.5 to 6 s
                apart, never evenly), sign in to their own account through POST /api/login, open
                the account page. The autofill user mistypes the password once and corrects it:
                one failed login, the case a "fails one login" rule must not punish.

"Hurt" means the person ended stopped. All 40 sign in, so a defense that flags an address, a
session or an account by mistake shows up as a shopper who did not get in. The people are spread
over about 15 seconds, the same span as the attacks.
"""

import os
import random
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import browsers  # noqa: E402
import population  # noqa: E402
from labclient import BASE_URL, product_skus  # noqa: E402
from demo_site.seed import password_for, username  # noqa: E402

MISTYPER = "autofill"


def _json_headers(p):
    ua = dict(browsers.headers_for(p.browser, "post", BASE_URL, BASE_URL + "/")).get("User-Agent", "")
    return [("User-Agent", ua), ("Accept", "application/json")]


def scenario_shop(p, client, rng):
    time.sleep(rng.uniform(0, 8))
    r = population._visit(p, client, "/", "typed")
    if r.status_code != 200:
        return population._stop(p, client, "blocked", r)
    time.sleep(rng.uniform(1.5, 4.0))
    r = population._visit(p, client, "/products?category=" + rng.choice(["shoes", "packs", "jackets"]), "link", BASE_URL + "/")
    if r.status_code != 200:
        return population._stop(p, client, "blocked", r)
    for sku in rng.sample(product_skus(r.text), rng.randint(2, 3)):
        time.sleep(rng.uniform(0.8, 3.0))
        r = population._visit(p, client, f"/product/{sku}", "link", BASE_URL + "/products")
        if r.status_code != 200:
            return population._stop(p, client, "blocked", r)
    time.sleep(rng.uniform(1.5, 3.0))
    attempts = [password_for(p.account)]
    if p.persona == MISTYPER:
        attempts.insert(0, password_for(p.account) + "x")            # a typo, then the right one
    for pw in attempts:
        r = client.post("/api/login", json={"email": username(p.account), "password": pw}, headers=_json_headers(p))
        if r.status_code == 200:
            break
        if r.status_code in (403, 429):
            return population._stop(p, client, "blocked", r)
        time.sleep(rng.uniform(2.0, 3.5))
    if r.status_code != 200:
        return population._stop(p, client, "failed", r)
    r = population._visit(p, client, "/account", "link", BASE_URL + "/")
    return population._stop(p, client, "logged_in" if r.status_code == 200 else "blocked", r)


population.SCENARIOS["ch3_shop"] = scenario_shop
