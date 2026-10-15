"""
W2 Ch7's shoppers: the real customers of a limited drop

Generates the traffic your model learns from and the real users every checkpoint measures false
positives on. Six human cohorts, each chosen because it breaks a naive bot rule somewhere:

  desktop          the "typical" shopper; ~15% sit behind corporate egress (4 shared addresses)
  mobile_cgnat     phones on carrier CGNAT: two addresses for the whole cohort, no mouse
  power_user       sneakerheads who know the drop: fast, few pages
  vpn              commercial VPN: hosting ASN, timezone != exit country
  privacy_browser  Firefox resistFingerprinting / Brave: UTC, generic GPU, canvas randomised per session
  keyboard_only    screen-reader and keyboard users: zero pointer events

Labels: some users sign in to long-standing accounts. Those sign-ins are the only "human" labels the
defender gets (defenses/labels.py), and they are NOT a random sample: privacy-browser and VPN users
rarely sign in. Every account is one of the store's seed users (user000..299@example.test).

This module provides the drop-day cohort (`people`, each Round's `people=` since contract 1.7),
registers the `drop_day` scenario, and makes the population wait for deferred orders (Round 4): a
customer whose order is cancelled at review is counted as hurt, like one who was blocked.
checkpoint.py imports it (population.py also auto-imports every tools/personas_*.py).
"""

import os
import random
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import population  # noqa: E402
import shopper  # noqa: E402
from labclient import world_pool  # noqa: E402
from shopper import (DEVICES, Persona, accept_language, desktop_behavior, fingerprint,  # noqa: E402
                     human_think, keyboard_behavior, mobile_behavior, pick_device, pick_locale, weighted)

COHORTS = {"desktop": 0.42, "mobile_cgnat": 0.25, "power_user": 0.10,
           "vpn": 0.08, "privacy_browser": 0.08, "keyboard_only": 0.07}
# P(signs in), the account is picked uniformly from the 300 seed users (about 45% are "long-standing")
LOGIN = {"desktop": 0.5, "mobile_cgnat": 0.4, "power_user": 0.7, "vpn": 0.3, "privacy_browser": 0.15, "keyboard_only": 0.5}
# Home pools of world.json -> (tz, languages, country): where the person lives
HOME = {"home_broadband": ("America/New_York", ["en-US", "en"], "US"),
        "home_cable": ("America/Chicago", ["en-US", "en"], "US"),
        "home_fiber": ("America/Los_Angeles", ["en-US", "en"], "US"),
        "home_eu": ("Europe/Berlin", ["de-DE", "de", "en"], "DE")}
HOME_WEIGHT = [3, 3, 3, 1]
CHECKPOINT_HUMANS = 200


def human_persona(rng, cohort, n):
    mobile = cohort == "mobile_cgnat"
    device = pick_device(rng, mobile=mobile)
    ua_key = rng.choice(DEVICES[device][6])
    if mobile:
        ip, locale = rng.choice(world_pool("mobile_cgnat")), ("America/New_York", ["en-US", "en"], "US", 1)
    elif cohort == "vpn":
        ip, locale = rng.choice(world_pool("consumer_vpn")), pick_locale(rng, countries=("ES", "US", "DE"))
    elif cohort == "desktop" and rng.random() < 0.15:
        ip, locale = rng.choice(world_pool("corporate")), ("America/New_York", ["en-US", "en"], "US", 1)
    else:
        pool = weighted(rng, list(HOME), HOME_WEIGHT)
        ip, locale = rng.choice(world_pool(pool)), (*HOME[pool], 1)
    fp = fingerprint(rng, device, locale, ua_key)
    behavior = mobile_behavior(rng) if mobile else desktop_behavior(rng)
    think, browse = human_think(6.0), rng.randint(1, 4 if mobile else 5)
    if cohort == "power_user":
        behavior, think, browse = desktop_behavior(rng, pace=2.0), human_think(2.0), rng.randint(0, 1)
    elif cohort == "keyboard_only":
        behavior, think = keyboard_behavior(rng), human_think(9.0)
    elif cohort == "privacy_browser":
        random_canvas = f"{rng.getrandbits(64):016x}"
        if rng.random() < 0.5:   # Firefox resistFingerprinting
            ua_key = "firefox_win"
            device = rng.choice(["win-nvidia", "win-intel", "win-amd"])
            fp = fingerprint(rng, device, locale, ua_key, canvas=random_canvas)
            fp.update(tz="UTC", langs=["en-US", "en"], gpu="Mozilla", hw=4,
                      screen=rng.choice(["1400x800", "1600x900", "1200x700"]))
            locale = ("UTC", ["en-US", "en"], locale[2], 1)
        else:                    # Brave: real values, farbled canvas
            fp = fingerprint(rng, device, locale, ua_key, canvas=random_canvas)
    account = rng.randrange(300) if rng.random() < LOGIN[cohort] else None
    return Persona(actor=f"human:{cohort}:{n:03d}", persona=cohort, browser=("ml",), ip=ip, account=account,
                   ua=shopper.UA[ua_key], accept_language=accept_language(locale[1]), fp=fp, behavior=behavior,
                   think=think, browse=browse)


def legit_personas(n, seed):
    rng = random.Random(seed)
    cohorts = rng.choices(list(COHORTS), weights=list(COHORTS.values()), k=n)
    return [human_persona(rng, c, i) for i, c in enumerate(cohorts)]


def people(seed=population.SEED, n=None):
    return legit_personas(n or CHECKPOINT_HUMANS, seed)


OUTCOME = {"confirmed": "bought", "blocked": "blocked", "cancelled": "cancelled", "sold_out": "sold_out",
           "pending": "pending"}


def scenario_drop_day(p, client, rng):
    shopper.shop(p, client, rng)
    p.result["outcome"] = OUTCOME.get(p.result.get("final"), "failed")
    return p.result


population.SCENARIOS["drop_day"] = scenario_drop_day
population.HURT |= {"cancelled"}                           # wrongly cancelled at review is as bad as blocked

_run = population.run


def _run_and_resolve(*args, **kw):
    results = _run(*args, **kw)
    shopper.resolve_pending(results)
    for r in results:
        r["outcome"] = OUTCOME.get(r.get("final"), r.get("outcome", "failed"))
    return results


population.run = _run_and_resolve


def summarize(results):
    """{cohort: {"people", "hurt", "cancelled"}}: the false-positive accounting, per cohort."""
    out = {}
    for r in results:
        row = out.setdefault(r["persona"], {"people": 0, "hurt": 0, "cancelled": 0})
        row["people"] += 1
        row["hurt"] += r.get("outcome") in population.HURT
        row["cancelled"] += r.get("outcome") == "cancelled"
    return out
