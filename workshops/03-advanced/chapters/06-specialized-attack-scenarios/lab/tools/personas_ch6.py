"""
W3 Ch6's shoppers: the same 40 people as the starter, doing what each economy's attacker does.

A defense that stops a scalper, a scraper or a farm is only as good as what it costs the people who
do the same things honestly, so every round runs the starter's 40 shoppers (home broadband, carrier-NAT
phones, VPN and privacy-relay users, an old Chrome, an autofill user, a no-JS Firefox) through a scenario
that mirrors the round's attack surface:

    scenario     round  what each person does
    -----------  -----  ----------------------------------------------------------------------------
    ch6_login    1      sign in through POST /api/login; a code challenge is completed from the lab
                        mailbox. Two people (the old Chrome and the autofill user) reuse a top-30
                        password, so Round 1's breach step-up asks them for a code: the honest cost.
    ch6_drop     2      land on the drop, read it for 1.1 to 2.5 s (the autofill user clicks in 1.2 to
                        1.6 s), buy one pair. The scalper is racing them for the same 50 units.
    ch6_browse   3      listing, then 3 to 7 product pages. The old Chrome is a researcher who compares
                        18 products: under the coverage ceiling, but not by much.
    ch6_signup   4      create an account through the HTML form; a code challenge is completed from the
                        mailbox. Six phones share one carrier address, so the egress cap asks three of
                        them for a code.
    ch6_ads      5      see an ad, read for 0.6 to 1.5 s (the autofill user: 0.4 to 0.6 s), click it. The
                        no-JS Firefox has the Referer stripped by its privacy settings.

"Hurt" means the person ended stopped. "Stepped up" means they were asked for a code and entered it:
friction, not harm. This module registers the scenarios; checkpoint.py imports it.
"""

import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import browsers  # noqa: E402
import population  # noqa: E402
from labclient import BASE_URL, csrf_of, form_fields, product_skus  # noqa: E402
from demo_site.seed import password_for, username  # noqa: E402

DROP_SKU = "lab-runner-9"
REUSERS = {"old_chrome": 20, "autofill": 21}       # seed users 020 and 021 use a top-30 password
RESEARCHER = "old_chrome"                          # compares 18 products
NO_REFERER = "no_js"                               # privacy settings strip the Referer
HAPPY_EXTRA = {"stepped_up", "registered", "clicked"}


def _json_headers(p, referer=None):
    ua = dict(browsers.headers_for(p.browser, "post", BASE_URL, referer or BASE_URL + "/")).get("User-Agent", "")
    h = [("User-Agent", ua), ("Accept", "application/json")]
    return h + ([("Referer", referer)] if referer else [])


def complete_code(p, client, email, headers):
    """Read the emailed code from the lab mailbox and enter it, as the customer would. True if it verified."""
    mail = client.get(f"/lab/mailbox/{email}").json()["messages"]
    codes = [m["code"] for m in mail if "code" in m]
    if not codes:
        return False
    r = client.post("/api/challenge/verify", json={"type": "otp", "answer": {"code": codes[-1]}}, headers=headers)
    return r.status_code == 200


def _wants_code(r):
    return r.status_code == 403 and ('"otp"' in r.text or 'data-challenge="otp"' in r.text)


# --- Round 1 ---------------------------------------------------------------------------------------

def scenario_login(p, client, rng):
    i = REUSERS.get(p.persona, p.account)
    email, headers = username(i), _json_headers(p)
    time.sleep(rng.uniform(0, 2))
    r = client.post("/api/login", json={"email": email, "password": password_for(i)}, headers=headers)
    if r.status_code == 200:
        return population._stop(p, client, "logged_in", r)
    if _wants_code(r):
        done = complete_code(p, client, email, headers) and client.get("/api/account", headers=headers).status_code == 200
        return population._stop(p, client, "stepped_up" if done else "blocked", r)
    return population._stop(p, client, "blocked" if r.status_code in (403, 429) else "failed", r)


# --- Round 2 ---------------------------------------------------------------------------------------

def scenario_drop(p, client, rng):
    time.sleep(rng.uniform(0, 2.5))
    r = population._visit(p, client, f"/drop/{DROP_SKU}", "typed")
    if r.status_code != 200:
        return population._stop(p, client, "blocked", r)
    fields = form_fields(r.text)
    time.sleep(rng.uniform(1.2, 1.6) if p.autofill else rng.uniform(1.1, 2.5))
    data = {"csrf": fields.get("csrf", ""), "email": f"{p.actor.replace(':', '.')}@example.test", "size": fields.get("size", "9") or "9"}
    r = population._post(p, client, f"/drop/{DROP_SKU}", data, BASE_URL + f"/drop/{DROP_SKU}")
    if r.status_code == 200 and "order-confirmed" in r.text:
        return population._stop(p, client, "bought", r)
    if r.status_code == 410:
        return population._stop(p, client, "sold_out", r)
    return population._stop(p, client, "blocked" if r.status_code in (403, 429) else "failed", r)


# --- Round 3 ---------------------------------------------------------------------------------------

def scenario_browse(p, client, rng):
    time.sleep(rng.uniform(0, 1.5))
    r = population._visit(p, client, "/products?category=" + rng.choice(["shoes", "packs", "jackets"]), "typed")
    if r.status_code != 200:
        return population._stop(p, client, "blocked", r)
    skus = product_skus(r.text)
    looking = 18 if p.persona == RESEARCHER else rng.randint(3, 7)
    for sku in rng.sample(skus, min(looking, len(skus))):
        time.sleep(rng.uniform(0.15, 0.5))
        r = population._visit(p, client, f"/product/{sku}", "link", BASE_URL + "/products")
        if r.status_code != 200:
            return population._stop(p, client, "blocked", r)
    return population._stop(p, client, "browsed", r)


# --- Round 4 ---------------------------------------------------------------------------------------

def scenario_signup(p, client, rng):
    time.sleep(rng.uniform(0, 2))
    r = population._visit(p, client, "/register", "typed")
    if r.status_code != 200:
        return population._stop(p, client, "blocked", r)
    csrf, email = csrf_of(r.text), f"{p.actor.replace(':', '.')}@example.test"
    time.sleep(rng.uniform(1.2, 1.6) if p.autofill else rng.uniform(1.5, 3.0))
    data = {"csrf": csrf, "name": "Pat Shopper", "email": email, "password": "Tr1ck-Horse-Battery-9"}
    r = population._post(p, client, "/register", data, BASE_URL + "/register")
    if r.status_code in (302, 303):
        return population._stop(p, client, "registered", r)
    if _wants_code(r):
        if complete_code(p, client, email, _json_headers(p)):
            r = population._post(p, client, "/register", data, BASE_URL + "/register")
            if r.status_code in (302, 303):
                return population._stop(p, client, "stepped_up", r)
        return population._stop(p, client, "blocked", r)
    return population._stop(p, client, "blocked" if r.status_code in (403, 429) else "failed", r)


# --- Round 5 ---------------------------------------------------------------------------------------

def scenario_ads(p, client, rng):
    referer = None if p.persona == NO_REFERER else "https://news.example/article"
    headers = _json_headers(p, referer)
    time.sleep(rng.uniform(0, 1.5))
    client.post("/api/ads/impression", json={"campaign": "camp-1"}, headers=headers)
    time.sleep(rng.uniform(0.4, 0.6) if p.autofill else rng.uniform(0.6, 1.5))
    r = client.post("/api/ads/click", json={"campaign": "camp-1"}, headers=headers)
    if r.status_code == 200 and r.json().get("counted"):
        return population._stop(p, client, "clicked", r)
    return population._stop(p, client, "blocked" if r.status_code in (403, 429) else "failed", r)


population.SCENARIOS.update({"ch6_login": scenario_login, "ch6_drop": scenario_drop, "ch6_browse": scenario_browse,
                             "ch6_signup": scenario_signup, "ch6_ads": scenario_ads})
population.HAPPY |= HAPPY_EXTRA                       # a completed code, a sign-up, a billed click are not harm


def summarize(results):
    """{persona: {"people", "hurt", "stepped_up"}}"""
    out = {}
    for r in results:
        row = out.setdefault(r["persona"], {"people": 0, "hurt": 0, "stepped_up": 0})
        row["people"] += 1
        row["hurt"] += r.get("outcome") in population.HURT
        row["stepped_up"] += r.get("outcome") == "stepped_up"
    return out
