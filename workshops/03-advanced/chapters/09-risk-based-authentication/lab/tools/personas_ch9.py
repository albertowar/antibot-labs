"""
Chapter 9 customers: the people a login defense must keep letting in.

The starter's 40 shoppers still browse and buy next to every attack (a login defense must not
touch them), and 80 account holders sign in, one person per account, built from
demo_site/ext/rba_world.py (COHORT): each has a seeded 90-day history in the store, and today's
login comes from the device and network rba_world.today() says. Most are the easy majority on their
own laptop at home; the rest are one of everything that makes risk-based authentication hurt:

    persona            n  today
    returning         54  own laptop or phone, home network
    cgnat_phone        6  own phone over the carrier's shared address
    new_device         3  a new laptop at home
    cleared_cookies    3  own laptop, cookies cleared
    traveller          3  own laptop, a hotel network in Germany
    vpn                3  own laptop through a commercial VPN
    shared_device      2  the family laptop, remembered for someone else's account
    no_inbox           2  own laptop; no longer has access to the email address on file
    forgot_home        2  forgot the password; resets it on their own laptop at home
    forgot_new_phone   2  forgot the password; resets it on a new phone over the carrier

The cohort over-represents the awkward cases on purpose (a real login stream is mostly
`returning`), so the friction rate it reports is a stress figure, not a forecast.

Each person signs in through the JSON API (POST /api/login), as the store's own pages would. When
the store asks for the emailed code they read their own inbox (/lab/mailbox stands in for it) and
type the code, except the `no_inbox` customers, who cannot. Outcomes: `logged_in`, `blocked`,
`stuck_on_challenge` (asked for a code they cannot get) and `stranded` (a reset parked for days);
the last three count as hurt. Every prompt a person met is recorded in their result (`prompts`),
which is how the checkpoint measures friction.

Shopper pauses are divided by SPEEDUP; the checkpoint and verify.py use the same value.
"""

import time
from dataclasses import dataclass

import browsers
import population
from labclient import BASE_URL, admin, world_pool
from demo_site.ext import rba_world as W
from demo_site.seed import password_for

SPEEDUP = 5.0
COHORT_PERSONAS = {name for name, _ in W.COHORT}

population.HURT.add("stranded")


@dataclass
class SignIn(population.Persona):
    rd: str = None              # the remembered-device cookie this browser carries, if any
    flow: str = "signin"        # "signin" | "forgot"
    email: str = ""


def _sleep(rng, lo, hi):
    time.sleep(rng.uniform(lo, hi) / SPEEDUP)


def api_headers(browser):
    ua = dict(browsers.headers_for(browser, "typed", BASE_URL))["User-Agent"]
    return [("User-Agent", ua), ("Accept", "application/json"), ("Accept-Language", "en-US,en;q=0.9"),
            ("Origin", BASE_URL)]


def latest(email, field):
    """The newest message in this person's own inbox that carries `field` (a code or a reset token)."""
    for msg in reversed(admin("GET", f"/lab/mailbox/{email}")["messages"]):
        if field in msg:
            return msg[field]
    return None


def cohort(seed=population.SEED):
    people = []
    counts = {}
    for idx, a in sorted(W.accounts().items()):
        if a.persona not in COHORT_PERSONAS:
            continue
        t = W.today(a)
        k = counts[a.persona] = counts.get(a.persona, -1) + 1
        ips = world_pool(t["pool"])
        people.append(SignIn(actor=f"human:{a.persona}:{k:02d}", persona=a.persona, browser=t["browser"],
                             ip=ips[a.home_slot % len(ips)], account=idx, email=a.email,
                             rd=W.rd_token(t["rd_of"], t["device"]) if t["device"] else None,
                             flow="forgot" if a.persona.startswith("forgot") else "signin"))
    return people


def people():
    """The round's population: the starter's 40 shoppers plus the sign-in cohort."""
    return population.personas() + cohort()


def _stop(p, client, outcome, r=None):
    return population._stop(p, client, outcome, r)


def _login(p, client, rng, password):
    h = api_headers(p.browser)
    r = client.post("/api/login", json={"email": p.email, "password": password}, headers=h)
    if r.status_code == 403 and (r.json().get("error") or {}).get("code") == "challenge_required":
        ctype = r.json()["error"]["challenge"]
        p.result.setdefault("prompts", []).append(ctype)
        if p.persona == "no_inbox":
            return _stop(p, client, "stuck_on_challenge", r)
        _sleep(rng, 8.0, 25.0)                       # open the mail app, copy the code
        code = latest(p.email, "code")
        r = client.post("/api/challenge/verify", json={"type": ctype, "answer": {"code": code}}, headers=h)
        if r.status_code != 200:
            return _stop(p, client, "stuck_on_challenge", r)
    elif r.status_code != 200:
        return _stop(p, client, "blocked" if r.status_code in (403, 429) else "failed", r)
    r = client.get("/api/account", headers=h)
    ok = r.status_code == 200 and r.json().get("email") == p.email
    return _stop(p, client, "logged_in" if ok else "failed", r)


def _forgot(p, client, rng):
    h = api_headers(p.browser)
    r = client.post("/api/password-reset", json={"email": p.email}, headers=h)
    if r.status_code != 200:
        return _stop(p, client, "blocked" if r.status_code in (403, 429) else "failed", r)
    _sleep(rng, 8.0, 25.0)
    new_password = f"new-{password_for(p.account)}"
    r = client.post("/api/password-reset/confirm", json={"token": latest(p.email, "token"), "password": new_password},
                    headers=h)
    if r.status_code == 202:
        p.result.setdefault("prompts", []).append("cooling_off")
        return _stop(p, client, "stranded", r)
    if r.status_code != 200:
        return _stop(p, client, "blocked" if r.status_code in (403, 429) else "failed", r)
    _sleep(rng, 2.0, 6.0)
    return _login(p, client, rng, new_password)


def scenario_signin(p, client, rng):
    if p.rd:
        client.set_cookie("rd", p.rd)
    _sleep(rng, 0.0, 5.0)
    if p.flow == "forgot":
        return _forgot(p, client, rng)
    _sleep(rng, 2.0, 6.0)                            # type the email and password
    return _login(p, client, rng, password_for(p.account))


def scenario_ch9(p, client, rng):
    """Browse for the starter's shoppers, sign in for the cohort."""
    if isinstance(p, SignIn):
        return scenario_signin(p, client, rng)
    return population.scenario_browse(p, client, rng)


population.SCENARIOS["ch9"] = scenario_ch9


def friction(results):
    """(prompted, total) over the sign-in cohort: how many met an emailed code or a cooling-off."""
    mine = [r for r in results if r.get("persona") in COHORT_PERSONAS]
    return sum(1 for r in mine if r.get("prompts")), len(mine)


if __name__ == "__main__":
    import json
    import random
    from labclient import LabClient
    for p in cohort()[:3]:
        print(json.dumps(scenario_signin(p, LabClient(p.actor, ip=p.ip), random.Random(1)), default=str))
