"""
Shared attacker library: the knob space the bot author controls

Every attack in this chapter is a scalper walking the same drop-day journey (tools/shopper.py). What the
attacker actually controls is a handful of *knobs*: which proxy pool, whether JavaScript runs, what the
behaviour looks like, how many pages to browse, whether to load assets, and whether to send an
Accept-Language header. Those knobs map, through the shopper engine, onto the server-side features the
defender's model scores.

This module is the attacker's whole world:

  KNOBS        the controllable knobs and their allowed values
  encode(cfg)  a config -> a fixed-order integer vector (the surrogate's X)
  persona_for  a config -> a realizable, INTERNALLY CONSISTENT Persona

"Consistent" matters. The fingerprint farm of W2 Ch7 lost to the anomaly detector because it randomised
fingerprint attributes independently and produced impossible devices (an Apple GPU on Win32). The
adversary here has learned that lesson: every persona this module builds is a real device shape, bought
from a fingerprint shop, so the only way to lower the model's score is to change knobs the model actually
keys on, not to invent a device that cannot exist. That is what makes the Round 2 evasion a *feature-space*
attack under realizability constraints, not noise.

Whose addresses. The attacker rents from two providers, both pools of data/world.json: a cheap cloud
provider (`cloud_vm`, $0.10/GB) and a residential-proxy network (`resi_us`, $4/GB, one exit per /64 so
every session looks like a different household). The extractor of Round 1 is a cheap one: it owns a few
boxes at each provider (CHEAP_BOXES) and probes from those, which is exactly what a per-address budget
punishes.

Not an attack on its own: imported by round1_extract, round2_evade and round4_rareclass.
"""

import os
import random
import sys
from itertools import product

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tools"))

import labclient  # noqa: E402  (runs the labnet guard)
import shopper  # noqa: E402
from shopper import (UA, Persona, accept_language, fingerprint, fixed_think,  # noqa: E402
                     human_think, pick_device)

# The knobs, in a fixed order. encode() walks this dict, so the order is the surrogate's feature order
# too. Keep values ordered cheapest/most-bot-like first.
KNOBS = {
    "pool": ["datacenter", "residential"],   # asn_type: the single strongest tell
    "js": ["off", "on"],                      # has_fp / has_beh: does the page collector run?
    "behavior": ["scripted", "humanized"],    # mouse/keys/scroll shape
    "browse": [0, 3],                         # product pages before the drop
    "assets": ["skip", "load"],               # images + css + js: asset_ratio
    "lang": ["absent", "present"],            # Accept-Language header
}
FEATURES = list(KNOBS)
POOL_NAME = {"datacenter": "cloud_vm", "residential": "resi_us"}   # data/world.json
USD_PER_GB = {"datacenter": 0.10, "residential": 4.0}
CHEAP_BOXES = 4              # addresses a cheap extractor owns at each provider

# A fingerprint shop's inventory: real US devices, each with its own canvas.
# The attacker buys these so every persona is internally consistent.
_INVENTORY = None


def inventory(n=300):
    global _INVENTORY
    if _INVENTORY is None:
        r = random.Random(99)
        out = []
        for _ in range(n):
            device = pick_device(r)
            ua_key = r.choice(shopper.DEVICES[device][6])
            locale = shopper.pick_locale(r, countries=("US",))
            out.append((fingerprint(r, device, locale, ua_key, canvas=f"{r.getrandbits(64):016x}"), ua_key, locale))
        _INVENTORY = out
    return _INVENTORY


def provider(kind):
    """Every address the attacker can rent for a pool knob (world.json)."""
    return labclient.world_pool(POOL_NAME[kind])


def cheap_boxes(kind):
    """The few addresses a cheap extractor owns at that provider."""
    return provider(kind)[:CHEAP_BOXES]


def fresh_addresses(kind):
    """The rest of the provider's addresses: none of them has been used by the extractor."""
    return provider(kind)[CHEAP_BOXES:]


def encode(cfg):
    """A config -> list of small ints, in KNOBS order. The surrogate's X row."""
    return [KNOBS[k].index(cfg[k]) for k in FEATURES]


def all_configs():
    """Every point in the knob grid (2*2*2*2*2*2 = 64 configs)."""
    return [dict(zip(FEATURES, combo)) for combo in product(*KNOBS.values())]


def random_config(rng):
    return {k: rng.choice(v) for k, v in KNOBS.items()}


def cost_rank(cfg):
    """Order configs cheapest-first for tie-breaking an evasion search."""
    return tuple(KNOBS[k].index(cfg[k]) for k in FEATURES)


def persona_for(cfg, rng, n, family, ip=None):
    """Turn a config into a realizable, internally consistent Persona.

    `ip` pins the source address (an extractor probing from its own boxes); None rents a different exit
    from the provider's pool for this session (a rotating proxy).
    """
    if ip is None:
        ip = rng.choice(provider(cfg["pool"]))
    on = cfg["js"] == "on"
    if on:
        fp, ua_key, locale = rng.choice(inventory())
        fp, ua, langs = dict(fp), UA[ua_key], locale[1]
        behavior = _humanized_behavior(rng) if cfg["behavior"] == "humanized" else _scripted_behavior(rng)
    else:
        # No JS: a plain HTTP client with a borrowed Chrome User-Agent. No fingerprint, no behaviour telemetry.
        fp, behavior, ua, langs = None, None, UA["chrome_win"], ["en-US", "en"]
    return Persona(actor=f"bot:{family}:{n:03d}", persona=family, browser=("advbot",), ip=ip, ua=ua,
                   browser_like=on, accept_language=accept_language(langs) if cfg["lang"] == "present" else None,
                   fp=fp, behavior=behavior,
                   think=human_think(6.0) if cfg["behavior"] == "humanized" else fixed_think(0.8),
                   browse=cfg["browse"], loads_assets=(cfg["assets"] == "load"), honeypot=0.0,
                   usd_per_gb=USD_PER_GB[cfg["pool"]], config=dict(cfg))


def _scripted_behavior(rng):
    """What page.click()/page.fill() produce: almost nothing (W2 Ch1)."""
    moves = rng.randint(0, 4)
    return {"mouse_moves": moves, "straightness": 1.0 if moves else None,
            "speed_cv": round(rng.uniform(0.0, 0.05), 3) if moves else None,
            "clicks": rng.randint(2, 3), "keys": 0, "key_cv": None,
            "touches": 0, "scrolls": 0, "first_input_ms": rng.randint(30, 120)}


def _humanized_behavior(rng):
    """A humanizer that is *almost* human. The attacker samples curved paths, jittered typing and
    scrolling, but from tighter distributions than real people (speed_cv, key_cv) and straighter paths.
    That residual regularity is the tell Round 2's adversarial training learns: on its own it is weak,
    but conditioned on an otherwise human-looking session it carries signal. Real desktop users
    (tools/shopper.desktop_behavior) spread much wider."""
    keys = rng.choice([0, 0, rng.randint(5, 40)])
    return {"mouse_moves": int(rng.lognormvariate(5.6, 0.4)),
            "straightness": round(min(1.0, rng.betavariate(8, 2)), 3),
            "speed_cv": round(rng.uniform(0.30, 0.55), 3),
            "clicks": rng.randint(3, 10), "keys": keys,
            "key_cv": round(rng.uniform(0.18, 0.34), 3) if keys else None,
            "touches": 0, "scrolls": rng.randint(4, 30),
            "first_input_ms": int(rng.lognormvariate(7.1, 0.4))}


def verdict(result):
    """What the attacker reads from one purchase attempt: 1 = refused, 0 = allowed.

    This is the single bit a decision oracle unavoidably leaks: the store has to act on the verdict, so
    the attacker always learns it. The gate's teaching-aid headers (X-Lab-Score, X-Lab-Signals) are NOT
    read: a production store would not send them (LAB_HEADERS=0), and this chapter is about what the
    200-or-403 alone gives away.
    """
    return 0 if shopper.succeeded(result) else 1
