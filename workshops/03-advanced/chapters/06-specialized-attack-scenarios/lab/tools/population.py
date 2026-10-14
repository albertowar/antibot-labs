"""
The shoppers: the other half of every measurement.

A defense is only as good as what it costs real customers. These simulated
shoppers browse like people (land, look, pick, pay) from the networks and
browsers real customers use, including the awkward ones every chapter has a
false-positive story about:

    persona          n  network                   why it is here
    ---------------  -- ------------------------  --------------------------------------
    home             24 home broadband, own IP    the easy majority (Chrome, Firefox, Safari)
    mobile_cgnat      8 2 carrier-NAT IPs, shared per-IP limits and shared-address rules
    consumer_vpn      3 commercial VPN egress     IP reputation
    private_relay     2 privacy relay             datacenter ranges that are really people
    old_chrome        1 Chrome 138, home          stale-version rules
    autofill          1 Chrome, 1.2-1.6 s forms   form timing and honeypot naming
    no_js             1 Firefox, JS disabled      JS cookies, proofs of work, collectors

Scenarios (what a shopper does): browse (catalog -> product -> cart -> checkout),
drop (land -> drop page -> buy), login (log in -> account). Chapters add their
own in tools/personas_<ch>.py and pass them in.

The shoppers are Python, not browsers. Where a browser would run the page's
JavaScript, a chapter's PAGE_HOOKS entry does the equivalent work (solve the
proof of work, post telemetry) and sleeps for what a browser would have taken.

    python tools/population.py --scenario browse --n 20
"""

import argparse
import json
import random
import sys
import threading
import time
from dataclasses import dataclass, field

import browsers
from labclient import BASE_URL, LabClient, csrf_of, form_fields, product_skus, world_pool

SEED = 7


@dataclass
class Persona:
    actor: str
    persona: str
    browser: tuple
    ip: str
    checkout_ip: str = None
    js: bool = True
    fill: tuple = (2.0, 6.0)
    autofill: bool = False
    account: int = None          # seed user index to log in as
    result: dict = field(default_factory=dict)


def personas(seed=SEED, n=None):
    rng = random.Random(seed)
    home = world_pool("home_broadband") + world_pool("home_cable")
    cgnat, vpn, relay = world_pool("mobile_cgnat"), world_pool("consumer_vpn"), world_pool("private_relay")
    rng.shuffle(home)
    desktop = ([("chrome", 153, "windows")] * 10 + [("chrome", 153, "macos")] * 5 + [("firefox", 155)] * 5 + [("safari", "macos")] * 4)
    phones = [("safari", "ios")] * 5 + [("chrome", 153, "android")] * 3
    people = []
    for i, b in enumerate(desktop):
        people.append(Persona(f"human:home:{i:02d}", "home", b, home.pop(), account=30 + i))
    for i, b in enumerate(phones):
        people.append(Persona(f"human:mobile_cgnat:{i:02d}", "mobile_cgnat", b, cgnat[0 if i < 6 else 1], account=60 + i))
    people[-1].ip, people[-1].checkout_ip = home.pop(), cgnat[1]        # leaves the house mid-checkout
    for i in range(3):
        people.append(Persona(f"human:consumer_vpn:{i:02d}", "consumer_vpn", ("chrome", 153, "windows"), vpn[i], account=70 + i))
    for i in range(2):
        people.append(Persona(f"human:private_relay:{i:02d}", "private_relay", ("safari", "macos"), relay[i], account=80 + i))
    people.append(Persona("human:old_chrome:00", "old_chrome", ("chrome", 138, "windows"), home.pop(), account=90))
    people.append(Persona("human:autofill:00", "autofill", ("chrome", 153, "windows"), home.pop(), fill=(1.2, 1.6), autofill=True, account=91))
    people.append(Persona("human:no_js:00", "no_js", ("firefox", 155), home.pop(), js=False, account=92))
    rng.shuffle(people)
    return people[:n] if n else people


# Hooks a chapter may add: what a shopper's browser would do after each page load
# (run the page's JavaScript: solve a challenge, post telemetry). fn(persona, client, response)
# returns None to keep the response, or a new response (e.g. the page fetched again after
# solving an interstitial) that the scenario continues with.
PAGE_HOOKS = []


def load_chapter_personas():
    """Import every tools/personas_*.py so its PAGE_HOOKS / SCENARIOS register (idempotent)."""
    import glob
    import importlib
    import os
    here = os.path.dirname(os.path.abspath(__file__))
    for path in sorted(glob.glob(os.path.join(here, "personas_*.py"))):
        importlib.import_module(os.path.basename(path)[:-3])


def _visit(p, client, path, kind, referer=None):
    r = client.get(path, browsers.headers_for(p.browser, kind, BASE_URL, referer), allow_redirects=False)
    for hook in PAGE_HOOKS:
        out = hook(p, client, r)
        if out is not None:
            r = out
    return r


def _post(p, client, path, data, referer, ip=None):
    return client.post(path, data, browsers.headers_for(p.browser, "post", BASE_URL, referer), ip=ip, allow_redirects=False)


def _stop(p, client, outcome, r=None):
    p.result.update(outcome=outcome, status=r.status_code if r is not None else None, requests=client.requests,
                    verdict=client.verdict())
    return p.result


def scenario_browse(p, client, rng):
    time.sleep(rng.uniform(0, 2))
    r = _visit(p, client, "/", "typed")
    if r.status_code != 200:
        return _stop(p, client, "blocked", r)
    time.sleep(rng.uniform(0.5, 2.0))
    r = _visit(p, client, "/products?category=" + rng.choice(["shoes", "packs", "jackets"]), "link", BASE_URL + "/")
    if r.status_code != 200:
        return _stop(p, client, "blocked", r)
    skus = product_skus(r.text)
    if not skus:
        return _stop(p, client, "error", r)
    sku = rng.choice(skus)
    time.sleep(rng.uniform(0.5, 1.5))
    r = _visit(p, client, f"/product/{sku}", "link", BASE_URL + "/products")
    if r.status_code != 200:
        return _stop(p, client, "blocked", r)
    fields = form_fields(r.text)
    time.sleep(rng.uniform(*p.fill))
    r = _post(p, client, "/cart/add", {"csrf": fields.get("csrf", ""), "sku": sku, "size": fields.get("size", ""), "qty": "1", "next": "/cart"},
              BASE_URL + f"/product/{sku}")
    if r.status_code >= 400:
        return _stop(p, client, "blocked", r)
    r = _visit(p, client, "/checkout", "link", BASE_URL + "/cart")
    if r.status_code != 200:
        return _stop(p, client, "blocked", r)
    fields = form_fields(r.text)
    time.sleep(rng.uniform(*p.fill))
    data = {"csrf": fields.get("csrf", ""), "email": f"{p.actor.replace(':', '.')}@example.test", "name": "Pat Shopper",
            "address": "1 Trail Way", "city": "Boulder", "postcode": "80301", "card": "4242424242424242", "exp": "12/29", "cvc": "123"}
    if p.autofill:
        data.update({k: data["email"] for k in fields if k in ("email2", "phone", "tel", "fullname", "website")})
    r = _post(p, client, "/checkout", data, BASE_URL + "/checkout", ip=p.checkout_ip)
    if r.status_code == 200 and "order-confirmed" in r.text:
        return _stop(p, client, "bought", r)
    return _stop(p, client, "blocked" if r.status_code in (403, 429) else "failed", r)


def scenario_drop(p, client, rng, sku="lab-hoodie-1"):
    time.sleep(rng.uniform(0, 6))
    r = _visit(p, client, "/", "typed")
    if r.status_code != 200:
        return _stop(p, client, "blocked", r)
    time.sleep(rng.uniform(0.5, 2.0))
    r = _visit(p, client, f"/drop/{sku}", "link", BASE_URL + "/")
    if r.status_code != 200:
        return _stop(p, client, "blocked", r)
    fields = form_fields(r.text)
    time.sleep(rng.uniform(*p.fill))
    data = {"csrf": fields.get("csrf", ""), "email": f"{p.actor.replace(':', '.')}@example.test", "size": fields.get("size", "M") or "M"}
    r = _post(p, client, f"/drop/{sku}", data, BASE_URL + f"/drop/{sku}", ip=p.checkout_ip)
    if r.status_code == 200 and "order-confirmed" in r.text:
        return _stop(p, client, "bought", r)
    if r.status_code == 410:
        return _stop(p, client, "sold_out", r)
    return _stop(p, client, "blocked" if r.status_code in (403, 429) else "failed", r)


def scenario_login(p, client, rng):
    from demo_site.seed import password_for, username
    i = p.account if p.account is not None else 100
    time.sleep(rng.uniform(0, 2))
    r = _visit(p, client, "/login", "typed")
    if r.status_code != 200:
        return _stop(p, client, "blocked", r)
    time.sleep(rng.uniform(*p.fill))
    r = _post(p, client, "/login", {"csrf": csrf_of(r.text), "email": username(i), "password": password_for(i), "next": "/account"}, BASE_URL + "/login")
    if r.status_code in (302, 303):
        r = _visit(p, client, "/account", "link", BASE_URL + "/login")
        return _stop(p, client, "logged_in" if r.status_code == 200 else "blocked", r)
    return _stop(p, client, "blocked" if r.status_code in (403, 429) else "failed", r)


SCENARIOS = {"browse": scenario_browse, "drop": scenario_drop, "login": scenario_login}


def run(scenario="browse", people=None, seed=SEED, n=None, threads=8, quiet=False):
    """Run every persona through a scenario concurrently. Returns the list of result dicts."""
    load_chapter_personas()
    people = people or personas(seed, n)
    fn = SCENARIOS[scenario] if isinstance(scenario, str) else scenario
    lock = threading.Semaphore(threads)

    def one(p, k):
        with lock:
            rng = random.Random(seed * 100 + k)
            client = LabClient(p.actor, ip=p.ip, rng=rng)
            p.result.update(actor=p.actor, persona=p.persona)
            try:
                fn(p, client, rng)
            except Exception as e:
                p.result.update(outcome="error", error=repr(e))
    ts = [threading.Thread(target=one, args=(p, k)) for k, p in enumerate(people)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    results = [p.result for p in people]
    if not quiet:
        print_results(results)
    return results


HAPPY = {"bought", "logged_in", "browsed"}
HURT = {"blocked", "stuck_on_challenge"}


def summarize(results):
    by = {}
    for r in results:
        row = by.setdefault(r["persona"], {"persona": r["persona"], "n": 0, "ok": 0, "hurt": 0, "other": 0})
        row["n"] += 1
        if r.get("outcome") in HAPPY:
            row["ok"] += 1
        elif r.get("outcome") in HURT:
            row["hurt"] += 1
        else:
            row["other"] += 1
    return sorted(by.values(), key=lambda x: x["persona"])


def print_results(results):
    print(f"\n{'persona':<16}{'n':>4}{'ok':>5}{'hurt':>6}{'other':>7}")
    for row in summarize(results):
        print(f"{row['persona']:<16}{row['n']:>4}{row['ok']:>5}{row['hurt']:>6}{row['other']:>7}")
    hurt = [r for r in results if r.get("outcome") in HURT]
    if hurt:
        print("\nShoppers a defense stopped:")
        for r in hurt:
            print(f"  {r['actor']:<28} {r.get('status')}  {r.get('verdict')}")
    other = [r for r in results if r.get("outcome") not in HAPPY | HURT]
    if other:
        print("\nShoppers who did not finish for another reason:")
        for r in other:
            print(f"  {r['actor']:<28} {r.get('outcome')} {r.get('status')} {r.get('error', '')}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    load_chapter_personas()
    ap.add_argument("--scenario", default="browse", choices=sorted(SCENARIOS))
    ap.add_argument("--n", type=int, default=None)
    ap.add_argument("--seed", type=int, default=SEED)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    out = run(args.scenario, seed=args.seed, n=args.n, quiet=args.json)
    if args.json:
        print(json.dumps(out, indent=1))
