"""
W4 Ch3's cohort: the starter's 40 shoppers plus the nine clients a crawler defense must not hurt.

Deterrence and monetization are only worth having if they never touch a customer, a reader or the
search engine that sends you traffic. Next to the 40 shoppers (tools/population.py) run:

  prefetch (5)   shoppers whose browser prefetches the links on the page they are reading
                 (Speculation Rules, "instant page" plugins). They follow every *visible* product
                 link and never a hidden or nofollow one. The maze's false positive if its entry
                 link is not hidden properly.
  reader (3)     text-mode and accessibility users (Lynx, w3m, ELinks). Their User-Agent is neither
                 a browser nor a declared crawler: the false positive of any rule that treats
                 "unfamiliar UA" as "bot".
  search (1)     LabSearchBot, the verified search crawler (signed, from its operator's published
                 range) that obeys robots.txt and indexes 30 product pages from the sitemap. Its
                 policy is search=allow: refusing, charging or mazing it costs you referrals.

Ground-truth labels: shoppers are `human:<persona>:<n>`; the nine are `legit:<name>:<n>`, so the
scoreboard keeps them out of "people hurt" and "bots stopped" and the checkpoint reports them in
their own table. What happened to a client comes from its responses: 403 is a stop, 402 is a
paywall, a `crawler-charged` header is a bill, and a page with `X-Robots-Tag: noindex` is a decoy
from the maze. ANY of those is a false positive for these nine ("blocked" in the results).

Round 5 adds a proof-of-work gate that every client without a verified identity meets on the catalogue.
The cohort's browsers behave like browsers: they read the interstitial, solve the puzzle (for real, so
the server verifies it), WAIT for what their device would have taken (hashes / device rate) and
reload. The prefetchers are desktop Chrome and solve; the readers are text-mode (no JavaScript) and
cannot, which is the honest false positive of the round; the signed search crawler is verified and is
never gated. A shopper whose device would need longer than PATIENCE_S gives up (and counts as hurt).

    persona        device                                   solves?
    -------------  ---------------------------------------  ----------------------------------
    desktops, VPN  a laptop browser, 4 workers: DESKTOP_MHS yes
    iOS phones     DESKTOP_MHS / 4                          yes
    Android phones DESKTOP_MHS / 16 (a budget phone)        yes, if it is quick enough
    prefetch       desktop Chrome                           yes
    reader, no_js  no JavaScript                            no: the interstitial is a wall

The phone ratios are assumptions, not measurements (W1 Ch6 measures them). The persona result gains a
`pow` entry: {"bits", "solves", "tried", "wait_s", "gave_up"}.

This module provides the chapter's cohort (`personas`, which checkpoint.py hands to every Round as
`people=`) and registers the `crawl_gov` scenario and the Round 5 page hook; checkpoint.py imports it,
so every round runs these clients.
"""

import json
import os
import re
import sys
import time
from urllib import robotparser

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "attacks"))

import browsers  # noqa: E402
import population  # noqa: E402
import pow_client  # noqa: E402
from _common import (CHROME_UA, SEARCHBOT_RANGE, SEARCHBOT_UA, extract_links, is_decoy,  # noqa: E402
                     searchbot_signer)
from labclient import BASE_URL, world_pool  # noqa: E402

SEARCH_PAGES = 30
DESKTOP_MHS = float(os.environ.get("DESKTOP_MHS", "4.0"))     # hashes/s a person's browser does, in millions
PATIENCE_S = float(os.environ.get("PATIENCE_S", "5.0"))       # how long a person waits on a puzzle
READER_UAS = ["Lynx/2.9.2 libwww-FM/2.14 SSL-MM/1.4.1 OpenSSL/3.0.13",
              "w3m/0.5.3+git20230121", "ELinks/0.17.1 (textmode; Linux; 80x24-2)"]
_STARTER_PERSONAS = population.personas


def personas(seed=population.SEED, n=None):
    people = _STARTER_PERSONAS(seed)
    for p in people:
        p.kind = "shopper"
    fiber, eu = world_pool("home_fiber"), world_pool("home_eu")
    for i in range(5):
        p = population.Persona(f"legit:prefetch:{i:02d}", "prefetch", ("tool",), fiber[i])
        p.kind, p.ua = "prefetch", CHROME_UA
        people.append(p)
    for i, ua in enumerate(READER_UAS):
        p = population.Persona(f"legit:reader:{i:02d}", "reader", ("tool",), eu[i], js=False)
        p.kind, p.ua = "reader", ua
        people.append(p)
    p = population.Persona("legit:search:00", "search", ("tool",), SEARCHBOT_RANGE[0])
    p.kind, p.ua = "search", SEARCHBOT_UA
    people.append(p)
    return people[:n] if n else people


class Tally:
    """What happened to one client, from its responses."""

    def __init__(self):
        self.served = self.blocked = self.paywalled = self.charged = self.mazed = 0

    def add(self, r):
        if r.status_code == 403:
            self.blocked += 1
        elif r.status_code == 402:
            self.paywalled += 1
        elif is_decoy(r):
            self.mazed += 1
        elif r.status_code == 200:
            self.served += 1
            self.charged += bool(r.headers.get("crawler-charged"))
        return r

    @property
    def hurt(self):
        return self.blocked + self.paywalled + self.charged + self.mazed


# --- Round 5: what a person's browser does when the store answers with the proof-of-work interstitial ----

def device_rate(p):
    """Hashes per second of the person's device; 0 means no JavaScript."""
    if not p.js:
        return 0.0
    return DESKTOP_MHS * 1e6 / {"android": 16, "ios": 4}.get(p.browser[-1], 1)


def _headers(p, kind, referer):
    if p.browser[0] == "tool":
        return [("User-Agent", p.ua), ("Accept", "text/html,*/*;q=0.8")]
    return browsers.headers_for(p.browser, kind, BASE_URL, referer)


def pow_hook(p, client, r):
    """After a page load: if the gate served the interstitial, behave like the browser would, and
    swap the retried page into `r` (a hook cannot return a response here)."""
    payload = pow_client.payload_of(r)
    if payload is None:
        return
    entry = p.result.setdefault("pow", {"bits": int(payload["difficulty"]), "solves": 0, "tried": 0, "wait_s": 0.0,
                                        "gave_up": False, "no_js": False})
    rate = device_rate(p)
    if not rate:
        entry["no_js"] = True
        return                                               # nothing runs: the wall stays a wall
    started = time.perf_counter()
    counter, tried, _ = pow_client.solve_payload(payload, max_hashes=int(rate * PATIENCE_S))
    if counter is None:                                      # would take longer than they will wait
        time.sleep(max(0.0, PATIENCE_S - (time.perf_counter() - started)))
        entry.update(gave_up=True, wait_s=round(entry["wait_s"] + PATIENCE_S, 2))
        return
    wait = tried / rate
    time.sleep(max(0.0, wait - (time.perf_counter() - started)))
    # fetch() from the page: same User-Agent and cookies, a JSON body (the pass is bound to IP + User-Agent)
    hdrs = [(k, v) for k, v in _headers(p, "post", r.url) if k.lower() != "content-type"]
    if not pow_client.redeem(client, payload, counter, hdrs):
        return
    entry.update(solves=entry["solves"] + 1, tried=entry["tried"] + tried, wait_s=round(entry["wait_s"] + wait, 2))
    r2 = client.get(r.url.replace(BASE_URL, ""), _headers(p, "link", BASE_URL + "/"), allow_redirects=False)
    r.__dict__.update(r2.__dict__)


def pow_summary(results):
    """Per persona: n, solved, gave up, no JS, bits, waits (seconds a person sat waiting, for the checkpoint)."""
    rows = {}
    for r in results:
        row = rows.setdefault(r["persona"], {"n": 0, "solved": 0, "gave_up": 0, "no_js": 0, "bits": 0, "waits": []})
        row["n"] += 1
        pw = r.get("pow")
        if not pw:
            continue
        row["no_js"] += bool(pw.get("no_js"))
        row["gave_up"] += bool(pw.get("gave_up"))
        row["solved"] += bool(pw.get("solves"))
        row["bits"] = max(row["bits"], pw.get("bits") or 0)
        if pw.get("solves"):
            row["waits"].append(pw["wait_s"])
    return rows


def print_pow(results):
    print(f"\n{'client':<16}{'n':>4}{'solved':>8}{'gave up':>9}{'no JS':>7}{'bits':>6}{'median wait':>13}")
    for name, row in sorted(pow_summary(results).items()):
        if not (row["solved"] or row["gave_up"] or row["no_js"]):
            continue
        waits = sorted(row["waits"])
        med = f"{waits[len(waits) // 2]:.2f} s" if waits else "-"
        print(f"{name:<16}{row['n']:>4}{row['solved']:>8}{row['gave_up']:>9}{row['no_js']:>7}{row['bits']:>6}{med:>13}")


def _finish(p, client, t, **extra):
    p.result.update(outcome="blocked" if t.hurt else "browsed", status=client.statuses[-1] if client.statuses else None,
                    requests=client.requests, verdict=client.verdict(), served=t.served, blocked=t.blocked,
                    paywalled=t.paywalled, charged=t.charged, mazed=t.mazed, **extra)
    return p.result


def _get(client, p, t, path, extra=()):
    r = client.get(path, headers=[("User-Agent", p.ua), ("Accept", "text/html,*/*;q=0.8"), *extra])
    pow_hook(p, client, r)          # Round 5: a client with a browser solves the gate's puzzle before the tally sees it
    return t.add(r)


def _product_links(html, visible_only=True):
    return list(dict.fromkeys(h for h, hidden in extract_links(html) if h.startswith("/product/") and not (hidden and visible_only)))


def scenario_prefetch(p, client, rng):
    """Read a listing page; the browser prefetches every visible product link (never a hidden one)."""
    t = Tally()
    r = _get(client, p, t, f"/products?page={rng.randint(1, 5)}")
    for href in _product_links(r.text)[:8]:
        _get(client, p, t, href)
        time.sleep(0.05)
    return _finish(p, client, t)


def scenario_reader(p, client, rng):
    """A text-mode user: home, a listing page, then a handful of product pages."""
    t = Tally()
    _get(client, p, t, "/")
    r = _get(client, p, t, f"/products?page={rng.randint(1, 5)}")
    links = _product_links(r.text)
    for href in rng.sample(links, min(len(links), rng.randint(3, 6))):
        _get(client, p, t, href)
        time.sleep(0.1)
    return _finish(p, client, t)


def scenario_search(p, client, rng):
    """LabSearchBot: signed, robots.txt first, then the first 30 product URLs in the sitemap."""
    t, signer = Tally(), searchbot_signer()

    def get(path):
        client.http.cookies.clear()
        sig = list(signer.headers(path.partition("?")[0], path.partition("?")[2]).items())
        return t.add(client.get(path, headers=[("User-Agent", p.ua), ("Accept", "*/*"), *sig]))

    rp = robotparser.RobotFileParser()
    rp.parse(get("/robots.txt").text.splitlines())
    urls = re.findall(r"<loc>[^<]*(/product/p\d{3})</loc>", get("/sitemap.xml").text)
    skipped = 0
    for path in urls[:SEARCH_PAGES]:
        if not rp.can_fetch("LabSearchBot", path):
            skipped += 1
            continue
        get(path)
        time.sleep(0.03)
    return _finish(p, client, t, skipped=skipped)


def scenario_crawl_gov(p, client, rng):
    kind = getattr(p, "kind", "shopper")
    fn = {"prefetch": scenario_prefetch, "reader": scenario_reader, "search": scenario_search}.get(kind)
    return fn(p, client, rng) if fn else population.scenario_browse(p, client, rng)


if pow_hook not in population.PAGE_HOOKS:
    population.PAGE_HOOKS.append(pow_hook)          # the shoppers' browser: solve the gate's puzzle, reload
population.SCENARIOS["crawl_gov"] = scenario_crawl_gov
