"""
The capstone's people: the 40 shoppers of the W2 Ch9 lab (tools/personas_ch9.py, a copy) plus the legitimate API
clients Workshop 3 must not hurt.

The API layer (level 5) has its own false-positive surface. A mobile app and a partner integration are legitimate
non-browser clients: if the GraphQL cost budget is too tight, the REST velocity limit too low or the token binding
too brittle, you break them. Three honest clients run next to every attack, in the same minute as the shoppers, and
a refusal of any of them is a person hurt (the round fails on it):

    human:api_mobile:00   a phone app on home Wi-Fi (Safari's TLS stack): signs in like its web view does, takes a
    human:api_mobile:01   token, then pages the REST catalogue four times, a few seconds apart (24 products a page)
    human:api_partner:00  a partner integration (a Chrome TLS stack, a corporate address): signs in, runs one small
                          GraphQL query for its storefront

Both sign in the way every client of this store does (the page's sensor report, the login token of level 4), because
those layers still stand in front of the API: the point of a capstone is that the layers compose. They page like
people page (a jittered pause between pages), because an app that polls on an exact timer is a regularity-detector
false positive, which is a lesson of its own (Round 2's discussion).

`scenario "capstone"` dispatches: an API client runs scenario_api_client(), everybody else runs W2 Ch9's
"ch9_drop". population.personas() is wrapped to append the three clients, so the starter's population runner,
checkpoint_core and tools/population.py all see 43 people.

    python tools/population.py --scenario capstone      # once, at the store's current level
"""

import re
import time

import personas_ch9
import population
import profile_replay
from labclient import world_pool

# actor -> (role, browser profile for headers and sensor, TLS family it claims, seed account, pool)
API_PEOPLE = {
    "human:api_mobile:00": ("mobile", "chrome-153-android-touch", "chrome", 110, "home_fiber", 0),
    "human:api_mobile:01": ("mobile", "safari-26-macos", "safari", 111, "home_fiber", 1),
    "human:api_partner:00": ("partner", "chrome-153-windows", "chrome", 112, "corporate", 0),
}
NONCE = re.compile(r"ShopSensor\.send\(\"([^\"]+)\"\)")


def api_people():
    out = []
    for actor, (role, profile, family, account, pool, k) in API_PEOPLE.items():
        out.append(population.Persona(actor, f"api_{role}", ("chrome", 153, "windows"), world_pool(pool)[k], account=account))
    return out


def _verdict(r):
    return r.headers.get("X-Lab-Verdict"), r.headers.get("X-Lab-Signals", "")


def scenario_api_client(p, client, rng):
    from demo_site.seed import password_for, username
    role, profile, family, account, _pool, _k = API_PEOPLE[p.actor]
    prof = profile_replay.profile(profile)
    p.result.update(profile=profile, role=role, behavior="api_" + role)
    client.ja4 = personas_ch9.CLAIMED_JA4[family]
    time.sleep(rng.uniform(0, 3))

    nav = profile_replay.headers(client, prof["navigation_headers"])
    r = client.get("/", nav, ip=p.ip)                                 # the app's web view opens the home page
    if r.status_code != 200:
        return population._stop(p, client, "blocked", r)
    post = profile_replay.headers(client, prof["post_headers"])
    fetch = profile_replay.headers(client, prof["fetch_headers"])
    m = NONCE.search(r.text)
    if prof.get("signals") is not None and m:
        client.post("/api/telemetry", headers=post, json={"kind": "sensor", "nonce": m.group(1), "signals": prof["signals"]})
    time.sleep(rng.uniform(0.3, 1.0))

    token = personas_ch9._login_token(client, fetch, post)
    r = client.post("/api/login", headers=post + [("X-Login-Token", token)],
                    json={"email": username(account), "password": password_for(account)})
    if r.status_code >= 400:
        p.result.update(stage="login")
        return population._stop(p, client, "blocked" if r.status_code in (403, 429) else "failed", r)
    time.sleep(rng.uniform(0.4, 1.2))
    r = client.get("/api/token", fetch)
    if r.status_code != 200:
        p.result.update(stage="token")
        return population._stop(p, client, "blocked" if r.status_code in (403, 429) else "failed", r)
    bearer = [("Authorization", f"Bearer {r.json()['token']}")]

    if role == "mobile":
        for offset in range(0, 96, 24):                               # four pages of 24, a person's pace
            time.sleep(rng.uniform(0.5, 1.4))
            r = client.get(f"/api/v1/products?limit=24&offset={offset}", fetch + bearer)
            if r.status_code != 200:
                p.result.update(stage=f"rest@{offset}")
                return population._stop(p, client, "blocked" if r.status_code in (403, 429) else "failed", r)
    else:
        time.sleep(rng.uniform(0.5, 1.4))
        r = client.post("/graphql", headers=post + bearer, json={"query": "{ products(limit: 8) { sku name price } }"})
        if r.status_code != 200:
            p.result.update(stage="graphql")
            return population._stop(p, client, "blocked" if r.status_code in (403, 429) else "failed", r)
    p.result.update(score=int(r.headers.get("X-Lab-Score") or 0), signals=r.headers.get("X-Lab-Signals", ""))
    return population._stop(p, client, "browsed", r)


def scenario_capstone(p, client, rng):
    if p.actor in API_PEOPLE:
        return scenario_api_client(p, client, rng)
    return personas_ch9.scenario_ch9_drop(p, client, rng)


population.SCENARIOS["capstone"] = scenario_capstone

_personas = population.personas


def personas(seed=population.SEED, n=None):
    """The starter's 40 people, plus the three API clients when the whole population is asked for."""
    people = _personas(seed, n)
    return people + api_people() if n is None else people


population.personas = personas
