"""
W4 Ch5's cohort: the starter's shoppers doing what each round's attacker does, as real customers.

The LLM attacks abuse four ordinary customer actions, so the measurement of "who gets hurt" has to be those
same four actions done by people. Each round runs the starter's 40 shoppers (tools/population.py: home
broadband, carrier-NAT phones, VPN and privacy-relay users, an old Chrome, an autofill user, a no-JS user)
through one scenario, from their own address and device, logged in as one of the seeded customers:

  review_r1    (20)  post a review of something they own. The texts are ordinary prose; two are the kind a
                     pre-LLM defense already held (an exact-duplicate pair, a one-line "Love it!"): an honest
                     cost that a moderator later approves.
  register     (20)  sign up for the first time. Two ask for the accessible text puzzle and must never be
                     blocked for it. A shopper who is served a puzzle and solves it is *friction*, not hurt;
                     the scoreboard counts people whose last request was a stop.
  catalog      (40)  read a listing page and open a few products. They never touch the off-screen block or a
                     honeypot SKU, and a screen reader never announces the decoys (the checkpoint checks the
                     container is aria-hidden).
  review_r4    (20)  post a review, as in Round 1, but these are everyday phrasings that trip a naive prompt-
                     injection deny-list: "ignore the instructions on the box", "you are now looking at the
                     only tee I wear", "disregard the one-star reviews".

Ground-truth labels are the starter's `human:<persona>:<n>`; what happened to a shopper comes from the
responses: 201 posted, 202 held for moderation, 403 refused. This module registers the scenarios and gives
each shopper a stable index (`p.idx`) so every text is used exactly once; checkpoint.py imports it.
"""

import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import browsers  # noqa: E402
import population  # noqa: E402
from labclient import BASE_URL  # noqa: E402  (also puts the lab root on sys.path)
from defenses.challenge_gate import pow_solve  # noqa: E402
from demo_site.seed import password_for, username  # noqa: E402

with open(os.path.join(HERE, "..", "data", "human_reviews.json")) as _f:
    TEXTS = json.load(_f)

_STARTER_PERSONAS = population.personas
population.HAPPY |= {"reviewed", "held", "registered"}


def personas(seed=population.SEED, n=None):
    people = _STARTER_PERSONAS(seed)
    for k, p in enumerate(people):
        p.idx = k
    return people[:n] if n else people


def _json_headers(p, referer=None):
    ua = dict(browsers.headers_for(p.browser, "link", BASE_URL))["User-Agent"]
    h = [("User-Agent", ua), ("Accept", "application/json"), ("Accept-Language", "en-US,en;q=0.9"),
         ("Content-Type", "application/json"), ("Origin", BASE_URL)]
    return h + ([("Referer", referer)] if referer else [])


def _page_headers(p, referer=None):
    return browsers.headers_for(p.browser, "link" if referer else "typed", BASE_URL, referer)


def _done(p, client, outcome, r=None, **extra):
    p.result.update(outcome=outcome, status=r.status_code if r is not None else None, requests=client.requests,
                    verdict=client.verdict(), **extra)
    return p.result


def _review(cohort):
    def scenario(p, client, rng):
        time.sleep(rng.uniform(0, 2))
        item = TEXTS[cohort][p.idx % len(TEXTS[cohort])]
        r = client.post("/api/login", json={"email": username(p.account), "password": password_for(p.account)},
                        headers=_json_headers(p))
        if r.status_code != 200:
            return _done(p, client, "blocked" if r.status_code in (403, 429) else "failed", r)
        client.get(f"/product/{item['sku']}", headers=_page_headers(p, BASE_URL + "/products"))
        time.sleep(rng.uniform(1.0, 2.5))                         # a person types
        r = client.post("/api/reviews", json={"sku": item["sku"], "rating": item["rating"], "title": "My review",
                                              "body": item["text"]}, headers=_json_headers(p, f"{BASE_URL}/product/{item['sku']}"))
        if r.status_code == 201:
            return _done(p, client, "reviewed", r)
        if r.status_code == 202:
            return _done(p, client, "held", r)
        return _done(p, client, "blocked" if r.status_code in (403, 429) else "failed", r)
    return scenario


def scenario_register(p, client, rng):
    """Sign up. If a puzzle is served, a person reads it for a few seconds, solves it (the answer key stands in
    for their eyes) and retries; that is friction, recorded as `challenged`."""
    time.sleep(rng.uniform(0, 2))
    mode = "text" if p.idx < 2 else "image"
    body = {"email": f"new_customer_{p.idx:02d}@mail.example", "password": f"Human-pass-{p.idx:02d}", "name": "Pat Shopper", "mode": mode}
    client.get("/register", headers=_page_headers(p))
    time.sleep(rng.uniform(*p.fill))
    r = client.post("/api/register", json=body, headers=_json_headers(p, BASE_URL + "/register"))
    challenged = False
    err = r.json().get("error", {}) if r.status_code == 403 else {}
    if err.get("code") == "challenge_required":
        challenged, chal = True, err["payload"]
        time.sleep(rng.uniform(1.5, 3.0))                          # reading the puzzle
        answer = client.get(f"/lab/llm/puzzle/{chal['token']}").json()["answer"]
        nonce = pow_solve(chal["token"], chal["pow_bits"]) if chal.get("pow_bits") else ""
        v = client.post("/api/challenge/verify", json={"type": "puzzle", "answer": {
            "token": chal["token"], "answer": answer, "nonce": nonce}}, headers=_json_headers(p))
        if v.status_code != 200:
            return _done(p, client, "stuck_on_challenge", v, challenged=True)
        r = client.post("/api/register", json=body, headers=_json_headers(p, BASE_URL + "/register"))
    if r.status_code == 201:
        return _done(p, client, "registered", r, challenged=challenged)
    return _done(p, client, "blocked" if r.status_code in (403, 429) else "failed", r, challenged=challenged)


def scenario_catalog(p, client, rng):
    """Read the first listing page, maybe the second, open a few products."""
    import re
    time.sleep(rng.uniform(0, 2))
    r = client.get("/products", headers=_page_headers(p))
    if r.status_code != 200:
        return _done(p, client, "blocked", r)
    skus = re.findall(r'class="product-card" data-sku="([^"]+)"', r.text)
    if rng.random() < 0.4:
        time.sleep(rng.uniform(0.3, 1.0))
        r = client.get("/products?page=2", headers=_page_headers(p, BASE_URL + "/products"))
        skus += re.findall(r'class="product-card" data-sku="([^"]+)"', r.text)
    for sku in rng.sample(skus, min(len(skus), rng.randint(2, 5))):
        time.sleep(rng.uniform(0.3, 1.0))
        r = client.get(f"/product/{sku}", headers=_page_headers(p, BASE_URL + "/products"))
        if r.status_code != 200:
            return _done(p, client, "blocked", r)
    return _done(p, client, "browsed", r)


population.SCENARIOS.update({"review_r1": _review("round1"), "review_r4": _review("round4"),
                             "register": scenario_register, "catalog": scenario_catalog})
