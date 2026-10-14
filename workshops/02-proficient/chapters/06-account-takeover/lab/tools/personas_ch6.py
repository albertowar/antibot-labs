"""
W2 Ch6's shoppers: the people who sign in while the stuffers run.

A login defense is only as good as what it costs the people who sign in honestly, so this chapter
replaces the starter's 40 browsing shoppers with 132 people who only sign in, in the cohorts that
break account defenses in production (every one is a seed user, user000..299@example.test):

    persona          n   who they are                                     which layer costs them
    ---------------  --  -----------------------------------------------  ----------------------------------
    returning        50  strong password, usual device, own home IP       nobody: they must never be stopped
    breached         12  users 018-029: a top-30 password, which is also  Round 3: an emailed code
                         in the stuffers' lists
    typo             15  one wrong password, then the right one           nobody (a wrong password is not a
                                                                         false positive)
    cgnat            35  one shared carrier-NAT address                   Round 1: the IP limit refuses the
                                                                         31st person onward
    new_device       20  a home sign-in on the usual device first, then   Round 4: an unrecognized device
                         a new phone over a different network             earns an emailed code

Each person signs in through POST /api/login, the way the SPA and the mobile app do. A step-up
is completed like a real customer would: read the code from the (lab) mailbox, post it to
/api/challenge/verify. "Hurt" means the shopper ended without a session; completing a code is
friction, counted separately in `stepped_up`.

This module swaps population.personas() for the chapter's cohort and registers the `ato_login`
scenario. checkpoint.py imports it, so every round runs these people.
"""

import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import browsers  # noqa: E402
import population  # noqa: E402
from labclient import BASE_URL, LabClient, world_pool  # noqa: E402
from demo_site.seed import password_for, username  # noqa: E402

BROWSER = ("chrome", 153, "windows")
COHORTS = (("returning", range(30, 80)), ("breached", range(18, 30)), ("typo", range(80, 95)),
           ("cgnat", range(95, 130)), ("new_device", range(130, 150)))
CGNAT = "cgnat"


def people(seed=population.SEED, n=None):
    homes = world_pool("home_broadband") + world_pool("home_cable") + world_pool("home_fiber")
    travel, carrier = world_pool("home_eu"), world_pool("mobile_cgnat")[0]
    out, h = [], 0
    for persona, accounts in COHORTS:
        for k, i in enumerate(accounts):
            ip = carrier if persona == CGNAT else (travel[k] if persona == "new_device" else homes[h])
            p = population.Persona(f"human:{persona}:{k:02d}", persona, BROWSER, ip, account=i)
            if persona == "new_device":
                p.home_ip = homes[h]
            out.append(p)
            h += persona != CGNAT
    return out[:n] if n else out


def _headers():
    ua = dict(browsers.headers_for(BROWSER, "post", BASE_URL, BASE_URL + "/login")).get("User-Agent", "")
    return [("User-Agent", ua), ("Accept", "application/json")]


def _sign_in(client, email, password):
    return client.post("/api/login", json={"email": email, "password": password}, headers=_headers())


def _complete_step_up(client, email):
    """Read the emailed code and enter it, as the customer would. True if a session now exists."""
    mail = client.get(f"/lab/mailbox/{email}").json()["messages"]
    codes = [m["code"] for m in mail if "code" in m]
    if not codes:
        return False
    r = client.post("/api/challenge/verify", json={"type": "otp", "answer": {"code": codes[-1]}}, headers=_headers())
    return r.status_code == 200


def _finish(p, client, r, email):
    """Turn the last sign-in response into the person's outcome."""
    if r.status_code == 200:
        p.result["outcome"] = "logged_in"
    elif r.status_code == 403 and "challenge_required" in r.text and '"otp"' in r.text:
        done = _complete_step_up(client, email) and client.get("/api/account").status_code == 200
        p.result["outcome"] = "stepped_up" if done else "blocked"
    else:
        p.result["outcome"] = "blocked" if r.status_code in (403, 429) else "failed"
    p.result.update(status=r.status_code, requests=client.requests, verdict=client.verdict())
    return p.result


def scenario_ato_login(p, client, rng):
    i, email = p.account, username(p.account)
    time.sleep(rng.uniform(0, 3))
    if p.persona == "new_device":
        # Earlier that day: the usual laptop at home. This builds the history Round 4 compares with.
        home = LabClient(p.actor, ip=p.home_ip, rng=rng)
        home.set_cookie("did", f"dev-{i}")
        _sign_in(home, email, password_for(i))
        client.set_cookie("did", f"newdev-{i}")             # now: a new phone, abroad
    else:
        client.set_cookie("did", f"dev-{i}")
    if p.persona == "typo":
        time.sleep(rng.uniform(0.5, 1.5))
        wrong = _sign_in(client, email, password_for(i) + "x")
        p.result["typo_rejected"] = wrong.status_code == 401
        time.sleep(rng.uniform(1, 2))
    return _finish(p, client, _sign_in(client, email, password_for(i)), email)


population.SCENARIOS["ato_login"] = scenario_ato_login
population.personas = people
population.HAPPY |= {"stepped_up"}                          # a completed code is friction, not harm


def summarize(results):
    """{persona: {"people", "hurt", "stepped_up", "typo_rejected"}}"""
    out = {}
    for r in results:
        row = out.setdefault(r["persona"], {"people": 0, "hurt": 0, "stepped_up": 0, "typo_rejected": 0})
        row["people"] += 1
        row["hurt"] += r.get("outcome") in population.HURT
        row["stepped_up"] += r.get("outcome") == "stepped_up"
        row["typo_rejected"] += bool(r.get("typo_rejected"))
    return out
