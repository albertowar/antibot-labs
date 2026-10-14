"""
Chapter 5 shoppers: the starter's 40 people, unlocking and redeeming the promo.

The `promo` scenario is land → open the promo → answer the quiz (unlock) → redeem,
with human pauses. It exercises exactly what the session signals read: every shopper
has a landing page, a session that ages while they read, and (if their browser runs
JavaScript) the `js_ok` cookie. The one phone that leaves the house redeems from a
second address, so it changes ASN mid-session the way a real traveller does.

A PAGE_HOOK does for a shopper what their browser would: it reads the per-session
nonce out of the page's one-line script and writes the `js_ok` cookie. The `no_js`
persona skips it, exactly as a NoScript user would, which is why it misses `js_ok`.

    python tools/population.py --scenario promo     # registered when tools/personas_*.py load
"""

import os
import re
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import population  # noqa: E402
from labclient import BASE_URL, form_fields  # noqa: E402

NONCE_RE = re.compile(r'var n = "([0-9a-f]+)"')


def js_cookie_hook(p, client, r):
    """After a page load, a JavaScript-running browser turns the nonce into the js_ok cookie."""
    if not getattr(p, "js", True):
        return None                               # no-JS clients never run the script
    if r.status_code != 200 or "js_ok=" not in r.text:
        return None
    m = NONCE_RE.search(r.text)
    if m:
        client.set_cookie("js_ok", m.group(1)[::-1])
    return None


def scenario_promo(p, client, rng):
    _visit, _post, _stop = population._visit, population._post, population._stop
    time.sleep(rng.uniform(0, 2))
    r = _visit(p, client, "/", "typed")                        # land: session created, js_ok set by the hook
    if r.status_code != 200:
        return _stop(p, client, "blocked", r)
    time.sleep(rng.uniform(0.5, 1.5))
    r = _visit(p, client, "/promo/", "link", BASE_URL + "/")
    if r.status_code != 200:
        return _stop(p, client, "blocked", r)
    fields = form_fields(r.text)
    time.sleep(rng.uniform(*p.fill))
    r = _post(p, client, "/promo/unlock", {"csrf": fields.get("csrf", ""), "answer": "7"}, BASE_URL + "/promo/")
    if r.status_code != 200:
        return _stop(p, client, "blocked" if r.status_code in (403, 429) else "failed", r)
    time.sleep(rng.uniform(*p.fill))
    r = _post(p, client, "/promo/redeem", {"csrf": fields.get("csrf", "")}, BASE_URL + "/promo/", ip=p.checkout_ip)
    if r.status_code == 200 and "voucher" in r.text:
        return _stop(p, client, "redeemed", r)
    return _stop(p, client, "blocked" if r.status_code in (403, 429) else "failed", r)


population.SCENARIOS["promo"] = scenario_promo
if js_cookie_hook not in population.PAGE_HOOKS:
    population.PAGE_HOOKS.append(js_cookie_hook)
