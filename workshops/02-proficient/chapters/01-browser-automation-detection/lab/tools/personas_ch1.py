"""
Chapter 1 shoppers: the 40 population personas, each shopping as a real browser profile.

tools/population.py's shoppers are Python, not browsers, so nobody runs the page's sensor for them.
This file registers the scenario "sensor_shop": each shopper replays the shopping trip of one
real-browser profile (tools/profiles/*.json, through tools/profile_replay.py): the profile's
headers in wire order, its sensor report, its click. The persona keeps its own source address
and label, so the scoreboard still counts it as a human.

Who replays which profile is fixed per persona, so a profile's false positives show up under the
same shopper in every run:

    no_js                     chrome-153-windows-nojs  (no sensor report: blocked from Round 1,
                                                        an accepted, measured cost)
    everyone else (39)        the other 12 profiles in turn, by persona name

Outcomes (from the API calls of the trip):

    browsed       /api/products and /api/cart/add both answered 200
    blocked       a 403 on the page or either call: a false positive (except no_js)

The checkpoint lists every shopper whose score reached the "suspicious" band (20-39): served,
but one rule away from a block.

    python tools/population.py --scenario sensor_shop      # once, at the store's current level
"""

import population
import profile_replay

NOJS = "chrome-153-windows-nojs"


def assignments(people):
    """actor -> profile name, deterministic."""
    profiles = [p["name"] for p in profile_replay.load_profiles() if p["name"] != NOJS]
    out = {}
    k = 0
    for p in sorted(people, key=lambda p: p.actor):
        if p.persona == "no_js":
            out[p.actor] = NOJS
        else:
            out[p.actor] = profiles[k % len(profiles)]
            k += 1
    return out


_ASSIGNED = {}


def profile_for(p):
    if not _ASSIGNED:
        _ASSIGNED.update(assignments(population.personas()))
    return _ASSIGNED.get(p.actor, profile_replay.load_profiles()[0]["name"])


def scenario_sensor_shop(p, client, rng):
    name = profile_for(p)
    p.result["profile"] = name
    out = profile_replay.trip(client, profile_replay.profile(name))
    p.result.update(page=out["page"], products=out["products"], cart=out["cart"], signals=out["signals"],
                    gate_ms=out["gate_ms"], score=out["score"])
    if 403 in (out["page"], out["products"], out["cart"]):
        return population._stop(p, client, "blocked", client.last)
    if out["products"] == 200 and out["cart"] == 200:
        return population._stop(p, client, "browsed", client.last)
    return population._stop(p, client, "failed", client.last)


population.SCENARIOS["sensor_shop"] = scenario_sensor_shop
