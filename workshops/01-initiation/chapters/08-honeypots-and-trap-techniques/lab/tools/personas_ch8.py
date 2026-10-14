"""
Chapter 8 shoppers: sign up for an account, the way real people do it.

The starter's shoppers are Python, not browsers, so a persona that depends on the page's CSS cannot just
"look" at it. This module gives them the one thing the trap chapter needs: the store's own stylesheet
(/static/css/traps.css, parsed by trapkit.parse_css) decides which fields have a layout box, which are
off-screen and which the Tab key reaches. Break the CSS and the personas see it break.

It also relabels some of the 40 so the chapter's false positives have names on the scoreboard:

    persona          n  what it is                                   hurt when
    ---------------- -- -------------------------------------------- ------------------------------------------
    screen_reader     2 keyboard / screen-reader users (home IP)      the honeypot takes focus (Tab lands on it
                                                                      and its label says "Phone")
    autofill          1 browser autofill, fills in 1.2-1.6 s          the honeypot has a layout box and a name or
                        (population.py)                               label it recognises; or the timing
                                                                      threshold is above 1.2 s
    search_crawler    1 a search engine crawler (datacenter IP),      a trap URL is not in robots.txt
                        counted as a "human" so hurting it shows up
                        in humans_hurt
    mobile_cgnat      8 phones behind two carrier addresses; they     sanctions are keyed on IP (the Round 4
                        post a review too                             bot shares the first address)
    (the rest)       28 home, VPN, relay, old Chrome, no-JS, ...      should be untouched

A shopper is HURT (outcome "trapped" or "blocked") if the store stopped, faked or quarantined anything
they did. The scenario asks the store directly: every response carries X-Lab-Signals, and a trap or
sanction signal on a human's request is a false positive even when the page looked fine. That is what
makes the silent harms (a dropped signup, a hidden review) visible. A review is also read back by a
fresh visitor, the check no human would think to do.

These are MODELS. Real autofill and screen readers differ by browser and version: in Round 2, also try
the form in your own browser with its autofill and password manager on.

    python tools/personas_ch8.py [--n 40]          # the shoppers alone, at whatever level the store runs
"""

import os
import random
import re
import sys
import time
from collections import deque
from urllib.parse import urljoin, urlparse

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import browsers  # noqa: E402
import population  # noqa: E402
import trapkit  # noqa: E402
from labclient import BASE_URL, LabClient, csrf_of, world_pool  # noqa: E402

population.HURT.add("trapped")                  # a shopper the traps flagged, whatever the page looked like

AUTOFILL_VOCAB = {"email": "email", "e-mail": "email", "phone": "phone", "tel": "phone", "mobile": "phone",
                  "website": "url", "url": "url", "company": "org", "name": "name"}
REAL = {"name": "name", "email": "email", "new-password": "password"}      # autocomplete values of the real fields
LEAVE_ALONE = ("leave", "empty", "blank")
CRAWLER_UA = "WorkshopSearchBot/1.0 (+https://kestrel.test/bot)"


# --- Who the shoppers are --------------------------------------------------------------------------

_base_personas = getattr(population.personas, "_ch8_base", population.personas)         # idempotent if imported twice


def _relabel(p, persona, i):
    p.persona, p.actor = persona, f"human:{persona}:{i:02d}"


def personas(seed=population.SEED, n=None):
    """The starter's 40, with 2 screen-reader users and a search crawler named."""
    people = _base_personas(seed, n)
    homes = [p for p in people if p.persona == "home"]
    for i, p in enumerate(homes[:2]):
        _relabel(p, "screen_reader", i)
    if len(homes) > 2:
        _relabel(homes[2], "search_crawler", 0)
        homes[2].ip = world_pool("cloud_vm")[-1]
    return people


personas._ch8_base = _base_personas
population.personas = personas


# --- What each kind of person does with the form ----------------------------------------------------

def _profile(p):
    user = p.actor.replace(":", "-")
    return {"name": "Pat Shopper", "email": f"{user}@example.test", "password": f"Pw-{user}-2026!",
            "phone": "+1 555 0100", "url": "https://example.com", "org": "Example Ltd"}


def _vocab(field, label):
    hints = " ".join([field.get("name") or "", field.get("id") or "", field.get("autocomplete") or "", label]).lower()
    return next((v for k, v in AUTOFILL_VOCAB.items() if k in hints), None)


def fill_form(p, fields, css, me):
    """The POST body this person would send: hidden inputs as they came, and the fields they touch."""
    data, touched = {}, []
    for f in fields:
        name, kind = f.get("name"), f.get("type", "text")
        if not name or kind in ("submit", "button"):
            continue
        if kind == "hidden":
            data[name] = f.get("value", "")                  # a browser submits hidden inputs as they are
        elif f.get("autocomplete") in REAL:
            data[name] = me[REAL[f["autocomplete"]]]         # the fields the form is for
        elif p.persona == "screen_reader":
            # Tab lands on anything with a box that is not tabindex=-1, and they answer what the label says
            if trapkit.tab_reachable(f, css) and not any(w in f["_label"].lower() for w in LEAVE_ALONE):
                data[name] = me.get(_vocab(f, f["_label"]) or "", "n/a")
                touched.append(name)
        elif p.autofill:
            # autofill fills what it recognises, if the field has a box (off-screen counts), focusable or not
            key = _vocab(f, f["_label"])
            if key and trapkit.box(f, css) != "none":
                data[name] = me[key]
                touched.append(name)
        # a sighted person never touches a field they cannot see (display:none, or off to the left)
    return data, touched


# --- The scenarios ----------------------------------------------------------------------------------

def scenario_signup(p, client, rng):
    if p.persona == "search_crawler":
        return crawl(p, client, rng)
    _visit, _post, _stop = population._visit, population._post, population._stop
    flagged = []
    time.sleep(rng.uniform(0, 1.5))
    r = _visit(p, client, "/", "typed")
    if r.status_code != 200:
        return _stop(p, client, "blocked", r)
    r = _visit(p, client, "/register", "link", BASE_URL + "/")
    if r.status_code != 200:
        return _stop(p, client, "blocked", r)
    flagged.append(trapkit.tripped(r))
    css = trapkit.parse_css(client.get("/static/css/traps.css").text)
    data, touched = fill_form(p, trapkit.parse_form(r.text), css, _profile(p))
    time.sleep(rng.uniform(p.fill[0], min(p.fill[1], 3.0)))      # read the form, type
    r = _post(p, client, "/register", data, BASE_URL + "/register")
    flagged.append(trapkit.tripped(r))
    if r.status_code in (403, 429):
        return _stop(p, client, "blocked", r)
    r = trapkit.follow(client, r, browsers.headers_for(p.browser, "link", BASE_URL, BASE_URL + "/register"))
    flagged.append(trapkit.tripped(r))
    p.result["touched_hidden"] = touched
    landed = r
    if p.persona == "mobile_cgnat" and r.status_code == 200:
        title = f"Warm feet all winter ({p.actor})"
        r = _visit(p, client, "/product/p003", "link", BASE_URL + "/account")
        resp = _post(p, client, "/review/p003", {"csrf": csrf_of(r.text), "rating": "5", "title": title,
                                                 "body": "Recommended."}, BASE_URL + "/product/p003")
        flagged.append(trapkit.tripped(resp))
        if resp.status_code in (403, 429):
            return _stop(p, client, "blocked", resp)
        stranger = LabClient(p.actor, ip=p.ip, rng=rng).get("/product/p003", browsers.headers_for(p.browser, "typed", BASE_URL))
        if title not in stranger.text:
            flagged.append(True)                              # published to nobody: the silent harm
    if any(flagged):
        return _stop(p, client, "trapped", r)
    return _stop(p, client, "logged_in" if landed.status_code == 200 and "/account" in landed.url else "failed", r)


def crawl(p, client, rng):
    """A search engine: reads robots.txt (RFC 9309), follows raw-HTML links two levels deep, no JS, no cookies kept."""
    hdrs = [("User-Agent", CRAWLER_UA), ("Accept", "text/html")]
    robots = trapkit.Robots(client.get("/robots.txt", hdrs).text)
    queue, seen, pages, flagged = deque([("/", 0)]), {"/"}, 0, False
    r = None
    while queue and pages < 80:
        path, depth = queue.popleft()
        r = client.get(path, hdrs)
        pages += 1
        flagged = flagged or trapkit.tripped(r)
        if r.status_code in (403, 429):
            return population._stop(p, client, "blocked", r)
        if depth == 2 or "text/html" not in r.headers.get("content-type", ""):
            continue
        for href in re.findall(r'<a [^>]*href="([^"#]+)"', r.text):
            url = urlparse(urljoin(path, href))
            target = url.path + (f"?{url.query}" if url.query else "")
            if url.netloc or target in seen or url.path.startswith(("/logout", "/lab/", "/whoami")):
                continue
            seen.add(target)
            if robots.allowed(target):
                queue.append((target, depth + 1))
    p.result["pages"] = pages
    return population._stop(p, client, "trapped" if flagged else "browsed", r)


population.SCENARIOS["signup"] = scenario_signup


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=None)
    args = ap.parse_args()
    population.run("signup", n=args.n)
