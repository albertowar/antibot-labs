"""
W3 Ch9's fans: 110 people who each want one pair, and what each does when the drop is sold first come or raffled.

A raffle that keeps the resellers out is worth nothing if it also keeps out the people it exists for, so every
round runs the same 110 fans next to the crews. They are not the starter's 40 shoppers: a raffle's false
positives are not "stopped at checkout", they are "excluded from the draw" and "merged with a stranger", so the
cast is built around the things an allocation rule gets wrong (demo_site/ext/raffle_world.py has the full table).

    cohort          n   why they are here                                           where they may pay
    --------------  --  ----------------------------------------------------------  --------------------------
    loyal           52  the easy majority: aged, orders, a card, an address         nowhere
    household        9  three households of three: one address, three accounts      Round 3: one entry per household
    apartment        5  five strangers in one building (five unit numbers)           Round 3: merged with each other
    shared_card      4  two couples paying with one card at two addresses            Round 3: merged by the card
    new_real_fan    12  accounts 1 to 5 days old; two never verified their email    Round 2: a quarter ticket
    power_user       8  aged, six to twelve orders                                  nowhere
    gift_buyer       6  the pair goes to someone else's door                        Round 4: held for review
    traveller        6  consumer-VPN and privacy-relay addresses                    nowhere (no check reads the IP)
    no_saved_card    8  no card on file: they add one when they win                 Round 4: a code at the claim

What each person does (scenarios):

  ch9_enter   sign in; ask the drop how it is sold. FIRST COME: view the page, wait for the opening second, react
              (0.6 to 3 s), buy. RAFFLE: enter once (the two unverified new fans follow the mail's link when the
              entry is refused for it, and enter again: stepped up, not hurt).
  ch9_claim   run after the draw (and after each re-draw): a winner claims. A gift buyer ships to a new address
              (held at Round 4). A no-card fan adds a card through the account page first (card_add), then claims
              and, at Round 4, enters the code the store emails.

Outcomes the checkpoint reads (after the last claim wave, from the store's report):
  bought      holds a paid pair            lost        did not win: a fair loss, not harm
  held        a claim waiting in review    sold_out    first come: the units were gone by the time they clicked
  excluded / over_merged / claim_blocked   HURT: an entry dropped by a rule, merged with another person, or a
                                           win that never became a pair

This module registers the scenarios; checkpoint.py imports it.
"""

import os
import random
import sys
import time
from calendar import timegm

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import browsers  # noqa: E402
import population  # noqa: E402
from labclient import BASE_URL, world_pool  # noqa: E402
from demo_site.ext import raffle_world as W  # noqa: E402

SPEEDUP = 5.0                    # the entry window is compressed: every fan pause before entering is divided by this
LOGIN_SPREAD_S = 3.0             # fans sign in over these seconds before the drop
ARRIVAL_S = 10.0                 # fans enter over this many seconds of "human time" (2 s at SPEEDUP 5)
REACTION = (0.6, 3.0)            # first come: seconds between the page opening and the click
HAPPY_EXTRA = {"entered", "lost", "claimed", "held", "stepped_up"}
HURT_EXTRA = {"excluded", "over_merged", "claim_blocked"}

BROWSERS = [("chrome", 153, "windows"), ("chrome", 153, "windows"), ("chrome", 153, "macos"), ("firefox", 155),
            ("safari", "macos"), ("safari", "ios"), ("chrome", 153, "android"), ("chrome", 153, "windows")]


def _headers(p, kind="post", referer=None):
    """The browser's User-Agent and a JSON Accept (the page's own fetch() calls): requests adds the content type."""
    ua = dict(browsers.headers_for(p.browser, "post", BASE_URL, referer)).get("User-Agent", "")
    return [("User-Agent", ua), ("Accept", "application/json")]


def people():
    """The 110 fans as Persona objects, each carrying its world account in `.acct`."""
    homes = world_pool("home_broadband") + world_pool("home_cable")
    vpn, relay = world_pool("consumer_vpn"), world_pool("private_relay")
    ips, out, group_ip = iter(homes), [], {}
    for a in W.fans():
        if a.group and a.group.startswith("hh"):                 # a household shares one connection
            ip = group_ip.setdefault(a.group, next(ips))
        elif a.cohort == "traveller":
            ip = vpn[a.n % len(vpn)] if a.n % 2 == 0 else relay[a.n % len(relay)]
        else:
            ip = next(ips)
        n = len(out)
        p = population.Persona(f"human:{a.cohort}:{a.n:03d}", a.cohort, BROWSERS[n % len(BROWSERS)], ip)
        p.acct = a
        out.append(p)
    return out


def person_ja4(p):
    import hashlib
    return "t13d1516h2_" + hashlib.sha256(repr(p.browser).encode()).hexdigest()[:12]      # a browser build, shared by many


def _login(p, client):
    a = p.acct
    r = client.post("/api/login", json={"email": a.email, "password": a.password}, headers=_headers(p))
    return r.status_code == 200


def _epoch(info):
    stamp = (info.get("drop_at") or "").rstrip("Z")
    if not stamp or info.get("drop_open"):
        return time.time()
    secs, _, frac = stamp.partition(".")
    return timegm(time.strptime(secs, "%Y-%m-%dT%H:%M:%S")) + (float("0." + frac) if frac else 0.0)


def _latest_code(client, email, kind):
    msgs = client.get(f"/lab/mailbox/{email}").json()["messages"]
    return next((m for m in reversed(msgs) if (m.get("kind") == kind if kind != "code" else "code" in m)), None)


def scenario_enter(p, client, rng):
    a = p.acct
    client.ja4 = person_ja4(p)
    time.sleep(rng.uniform(0, LOGIN_SPREAD_S))                       # people do not all sign in the same second
    if not _login(p, client):
        return population._stop(p, client, "blocked", client.last)
    info = client.get(f"/api/raffle/{W.SKU}", headers=_headers(p, "link")).json()
    if info["mode"] == "first_come":
        client.get(f"/api/products/{W.SKU}", headers=_headers(p, "link"))                  # read the drop page
        wait = max(_epoch(info) + rng.uniform(*REACTION) - time.time(), 1.1)                # react to the opening
        time.sleep(wait)
        r = client.post("/api/buy", json={"sku": W.SKU, "size": W.SIZE, "email": a.email}, headers=_headers(p))
        if r.status_code == 201:
            return population._stop(p, client, "bought", r)
        return population._stop(p, client, "sold_out" if r.status_code == 410 else "blocked", r)
    time.sleep(rng.uniform(0, ARRIVAL_S) / SPEEDUP)
    r = client.post(f"/api/raffle/{W.SKU}/enter", json={}, headers=_headers(p))
    if r.status_code == 403 and "unverified_email" in r.headers.get("X-Lab-Signals", ""):  # the page said: verify your email
        link = _latest_code(client, a.email, "verify")
        if link:
            client.get(link["verify_url"], headers=_headers(p, "link"))
            r = client.post(f"/api/raffle/{W.SKU}/enter", json={}, headers=_headers(p))
            if r.status_code == 201:
                p.result["verified_link"] = True
    if r.status_code == 201:
        return population._stop(p, client, "entered", r)
    return population._stop(p, client, "blocked" if r.status_code in (403, 429) else "failed", r)


def scenario_claim(p, client, rng):
    """A winner pays. A fan who is not a winner (or already holds a pair) does nothing."""
    a = p.acct
    if p.result.get("claimed"):
        return p.result
    client.ja4 = person_ja4(p)
    if not _login(p, client):
        return p.result
    me = client.get(f"/api/raffle/{W.SKU}/me", headers=_headers(p, "link")).json()
    if me.get("status") != "won":
        return p.result
    body = {}
    if a.cohort == "gift_buyer":
        line1, city, post = W.gift_address(a.n)
        body = {"line1": line1, "city": city, "postcode": post}
    if a.cohort == "no_saved_card":                              # add a card through the account page, then claim
        number = W.card_number("411111", f"nsc-card-{a.n}")
        client.post("/api/account/card", json={"card": number}, headers=_headers(p))
    for _ in range(2):
        r = client.post(f"/api/raffle/{W.SKU}/claim", json=body, headers=_headers(p))
        if r.status_code in (201, 202):
            p.result["claimed"] = True
            p.result["claim_status"] = r.status_code
            if p.result.get("code_entered"):
                p.result["stepped_up"] = True
            return population._stop(p, client, "claimed" if r.status_code == 201 else "held", r)
        ct = r.headers.get("Content-Type", "")
        err = r.json().get("error", {}) if ct.startswith("application/json") else {}
        if err.get("code") == "challenge_required":
            code = _latest_code(client, a.email, "code")
            v = client.post("/api/challenge/verify", json={"type": "otp_session", "answer": {"code": (code or {}).get("code", "")}},
                            headers=_headers(p))
            if v.status_code == 200:
                p.result["code_entered"] = True
                continue
        break
    return population._stop(p, client, "claim_blocked", client.last)


population.SCENARIOS.update({"ch9_enter": scenario_enter, "ch9_claim": scenario_claim})
population.HAPPY |= HAPPY_EXTRA
population.HURT |= HURT_EXTRA


def summarize(results):
    """{cohort: {"people", "hurt", "stepped_up"}}"""
    out = {}
    for r in results:
        row = out.setdefault(r["persona"], {"people": 0, "hurt": 0, "stepped_up": 0})
        row["people"] += 1
        row["hurt"] += r.get("outcome") in population.HURT
        row["stepped_up"] += bool(r.get("stepped_up") or r.get("verified_link"))
    return out
