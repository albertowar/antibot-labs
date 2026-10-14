"""
Chapter 6 shoppers: sign up, then claim the promo voucher, the way a person does it.

The shoppers in tools/population.py are Python, not browsers. Where a real browser would run the
page's JavaScript, this module does the equivalent: a PAGE_HOOK plays the Turnstile widget (mints a
token from the mock provider when the page carries a `.cf-turnstile` box), and the scenario below
plays captcha.js (reads the image through the lab's simulated "eyes", types it, loses a few seconds
doing so).

It also relabels some of the 40 so the chapter's false positives have names on the scoreboard:

    persona         n  what it is                                   hurt when
    --------------- -- -------------------------------------------- -----------------------------------
    screen_reader    2 blind users with a screen reader (home IP)    the moment an image CAPTCHA is served:
                                                                     there is no audio or alternative path
    deep_link        3 arrive from an email link, skip the home page  Round 4: challenged (risk), but they solve it
    hopper           1 deep-linker on a phone: Wi-Fi -> cellular      Round 4: stepped up once (new IP), then passes
                       between seeing the image and answering it
    no_js            1 JavaScript off (population.py)                 Round 1+: no widget, no token, no sign-up
    (the rest)      32 home, CGNAT phones, VPN, relay, ...            should be untouched

Human models (assumptions, not data): first-try reading accuracy 97% (basic image) / 88% (hardened),
in the range Bursztein et al. measured for distorted text (2010); 3-15 simulated seconds to read and
type (lognormal, median 6); 25% give up after a wrong answer. Time is simulated (LAB_TIME_SCALE=5).

    python tools/personas_ch6.py [--n 40]          # the shoppers alone, at whatever level the store runs
"""

import json
import math
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import browsers  # noqa: E402
import captcha_kit as ck  # noqa: E402
import population  # noqa: E402
from labclient import BASE_URL, csrf_of, form_fields  # noqa: E402

TOKEN_FIELD = "cf-turnstile-response"
ABANDON_AFTER_FAIL = 0.25
HUMAN_ACCURACY = {"basic": 0.97, "hardened": 0.88}
ACTION = re.compile(r'class="cf-turnstile"[^>]*data-action="([^"]+)"')

population.HAPPY.add("redeemed")          # a shopper who got the voucher is a happy shopper


# --- Who the shoppers are --------------------------------------------------------------------------

_base_personas = getattr(population.personas, "_ch6_base", population.personas)      # idempotent if imported twice


def _relabel(p, persona, i):
    p.persona, p.actor = persona, f"human:{persona}:{i:02d}"


def personas(seed=population.SEED, n=None):
    """The starter's 40, with 2 screen-reader users, 3 deep-linkers and the Wi-Fi -> cellular hopper (a fourth deep-linker) named."""
    people = _base_personas(seed, n)
    homes = [p for p in people if p.persona == "home"]
    for i, p in enumerate(homes[:2]):
        _relabel(p, "screen_reader", i)
    for i, p in enumerate(homes[2:5]):
        _relabel(p, "deep_link", i)
    for p in people:
        if p.checkout_ip:                  # the starter's persona who leaves home mid-checkout
            _relabel(p, "hopper", 0)
    return people


personas._ch6_base = _base_personas
population.personas = personas


# --- The widget (a PAGE_HOOK: what the provider's script does in a browser) ----------------------------

def widget_hook(p, client, r):
    """After each page load: for every Turnstile box on it, pass the (non-interactive) widget and keep the token."""
    if r.status_code != 200 or not p.js or "cf-turnstile" not in r.text:
        return None
    for action in ACTION.findall(r.text):
        p.result.setdefault("tokens", {})[action] = ck.mint_token(client.current_ip(), action, hostname=ck.host_of(BASE_URL))
    return None


if not any(h.__name__ == "widget_hook" for h in population.PAGE_HOOKS):
    population.PAGE_HOOKS.append(widget_hook)


# --- The scenario -----------------------------------------------------------------------------------------

def read_time(rng):
    return min(15.0, max(3.0, rng.lognormvariate(math.log(6.0), 0.35)))


def _json_headers(p, referer):
    hdrs = [(k, v) for k, v in browsers.headers_for(p.browser, "post", BASE_URL, referer) if k.lower() != "content-type"]
    return hdrs + [("Content-Type", "application/json"), ("Accept", "application/json")]


def solve_like_a_person(p, client, rng, payload, referer):
    """Read the image through the simulated eyes, type it. Returns True when the store cleared the session."""
    ck.sim_sleep(read_time(rng))
    seen = ck.look_at(payload["id"]) or ""
    style = "hardened" if p.result["level"] >= 3 else "basic"
    text = seen if rng.random() < HUMAN_ACCURACY[style] else ck.typo(seen or "AAAAA", rng)
    ip = None
    if p.persona == "hopper" and p.result["captchas"] == 1:      # Wi-Fi -> cellular between the image and the answer
        client.ip = p.checkout_ip
    r = client.post("/api/challenge/verify", headers=_json_headers(p, referer), json={"type": "captcha", "answer": {"id": payload["id"], "text": text}}, ip=ip)
    return r.status_code == 200


def scenario_signup(p, client, rng):
    """Land (unless deep-linked), create an account, claim the $10 voucher."""
    p.result["level"] = ck.store_level()
    p.result["captchas"] = 0
    ck.sim_sleep(rng.uniform(0, 4))
    deep = p.persona in ("deep_link", "hopper")                          # arrived from an email: no home page first
    if not deep:
        population._visit(p, client, "/", "typed")
        ck.sim_sleep(rng.uniform(2, 5))                                  # look around
    r = population._visit(p, client, "/register", "typed" if deep else "link", BASE_URL + "/")
    if r.status_code != 200:
        return population._stop(p, client, "blocked", r)
    ck.sim_sleep(rng.uniform(4, 9))                                      # fill in the form
    data = {"csrf": csrf_of(r.text), "name": "Pat Shopper", "email": f"{p.actor.replace(':', '.')}@example.test",
            "password": "correct horse battery"}
    token = p.result.get("tokens", {}).get("register")
    if token:
        data[TOKEN_FIELD] = token
    r = population._post(p, client, "/register", data, BASE_URL + "/register")
    p.result["registered"] = r.status_code in (302, 303)
    if not p.result["registered"]:
        return population._stop(p, client, "blocked" if r.status_code in (403, 429) else "failed", r)

    r = population._visit(p, client, "/promo/", "link", BASE_URL + "/account")
    ck.sim_sleep(rng.uniform(1, 3))
    for _ in range(4):                                                   # claim; initial try + step-ups / retries
        r = client.post("/promo/redeem", headers=_json_headers(p, BASE_URL + "/promo/"), json={})
        if r.status_code == 200:
            return population._stop(p, client, "redeemed", r)
        err = r.json().get("error", {}) if r.headers.get("content-type", "").startswith("application/json") else {}
        if err.get("code") != "challenge_required":
            return population._stop(p, client, "blocked" if r.status_code in (403, 429) else "failed", r)
        p.result["captchas"] += 1
        if p.persona == "screen_reader":
            p.result["inaccessible"] = True                               # an image, and nothing else to try
            return population._stop(p, client, "stuck_on_challenge", r)
        if not solve_like_a_person(p, client, rng, err["payload"], BASE_URL + "/promo/"):
            if p.persona != "hopper" and rng.random() < ABANDON_AFTER_FAIL:
                p.result["abandoned"] = True
                return population._stop(p, client, "stuck_on_challenge", r)
    return population._stop(p, client, "stuck_on_challenge", r)


population.SCENARIOS["signup"] = scenario_signup


# --- Reporting (for tools/checkpoint.py) ----------------------------------------------------------------------

def summary(results):
    rows = {}
    for r in results:
        row = rows.setdefault(r["persona"], {"n": 0, "registered": 0, "challenged": 0, "captchas": 0, "got_voucher": 0, "lost": 0})
        row["n"] += 1
        row["registered"] += bool(r.get("registered"))
        row["challenged"] += bool(r.get("captchas"))
        row["captchas"] += r.get("captchas", 0)
        row["got_voucher"] += r.get("outcome") == "redeemed"
        row["lost"] += r.get("outcome") in population.HURT
    return rows


def print_summary(results):
    print(f"\n{'persona':<16}{'n':>4}{'signed up':>11}{'got voucher':>13}{'challenged':>12}{'CAPTCHAs':>10}{'lost':>6}")
    for name, row in sorted(summary(results).items()):
        print(f"{name:<16}{row['n']:>4}{row['registered']:>11}{row['got_voucher']:>13}{row['challenged']:>12}{row['captchas']:>10}{row['lost']:>6}")
    reasons = {"screen_reader": "image-only CAPTCHA, no audio or alternative path", "no_js": "no JavaScript: no widget, no token"}
    for r in results:
        if r.get("outcome") in population.HURT:
            why = reasons.get(r["persona"], "gave up after a wrong answer" if r.get("abandoned") else "stopped")
            print(f"  lost: {r['actor']:<28} {why}")


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=None)
    args = ap.parse_args()
    out = population.run("signup", n=args.n, quiet=True)
    print_summary(out)
