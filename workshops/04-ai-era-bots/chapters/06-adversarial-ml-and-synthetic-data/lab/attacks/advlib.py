"""
W4 Ch6 — Shared attacker library: the knob space the bot author controls

Every attack in this chapter is a scalper walking the same drop-day journey
(tools/shopper.py). What the attacker actually controls is a handful of
*knobs*: which proxy pool, whether JS runs, what the behavior looks like,
how many pages to browse, whether to load assets, and whether to send an
Accept-Language header. Those knobs map, through the shopper engine, onto
the server-side features the defender's model scores.

This module is the attacker's whole world:

  KNOBS        the controllable knobs and their allowed values
  encode(cfg)  a config -> a fixed-order integer vector (the surrogate's X)
  persona_for  a config -> a realizable, INTERNALLY CONSISTENT Persona

"Consistent" matters. The farm attack of W2 Ch7 lost to the anomaly
detector because it randomized fingerprint attributes independently and
produced impossible devices (an Apple GPU on Win32). The adversary here has
learned that lesson: every persona this module builds is a real device
shape, so the only way to lower the model's score is to change knobs the
model actually keys on, not to invent a device that cannot exist. That is
what makes the Round 2 evasion a *feature-space* attack under realizability
constraints, not noise.

Not an attack on its own: imported by round1_extract, round2_evade and
round4_rareclass.
"""

import hashlib
import os
import random
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))

import labclient as labnet  # noqa: E402
import shopper  # noqa: E402
from shopper import (UA, Persona, browser_headers, fingerprint,  # noqa: E402
                     fixed_think, human_think, pick_device)

# The knobs, in a fixed order. encode() walks this dict, so the order is the
# surrogate's feature order too. Keep values ordered cheapest/most-bot-like first.
KNOBS = {
    "pool": ["datacenter", "residential"],   # asn_type: the single strongest tell
    "js": ["off", "on"],                      # has_fp / has_beh: does the page collector run?
    "behavior": ["scripted", "humanized"],    # mouse/keys/scroll shape
    "browse": [0, 3],                         # product pages before the drop
    "assets": ["skip", "load"],               # images + css + js: asset_ratio
    "lang": ["absent", "present"],            # Accept-Language header
}
FEATURES = list(KNOBS)
CHEAPEST = {k: v[0] for k, v in KNOBS.items()}

# A fingerprint shop's inventory: real US devices, each with its own canvas.
# The attacker buys these so every persona is internally consistent.
_INVENTORY = None


def inventory(rng=None, n=300):
    global _INVENTORY
    if _INVENTORY is None:
        r = rng or random.Random(99)
        out = []
        for _ in range(n):
            device = pick_device(r)
            ua_key = r.choice(shopper.DEVICES[device][6])
            locale = shopper.pick_locale(r, countries=("US",))
            out.append((fingerprint(r, device, locale, ua_key,
                                    canvas=f"{r.getrandbits(64):016x}"), ua_key, locale))
        _INVENTORY = out
    return _INVENTORY


def encode(cfg):
    """A config -> list of small ints, in KNOBS order. The surrogate's X row."""
    return [KNOBS[k].index(cfg[k]) for k in FEATURES]


def all_configs():
    """Every point in the knob grid (2*2*2*2*2*2 = 64 configs)."""
    from itertools import product
    return [dict(zip(FEATURES, combo)) for combo in product(*KNOBS.values())]


def random_config(rng):
    return {k: rng.choice(v) for k, v in KNOBS.items()}


def persona_for(cfg, rng, actor="advbot", cohort="advbot", ip=None):
    """Turn a config into a realizable, internally consistent Persona.

    `ip` pins the source address (same pool semantics, chosen /24) so an
    extractor can concentrate probes on a few cheap datacenter /24s.
    """
    pool = labnet.Pool(cfg["pool"], country="US", rng=rng)
    if ip is None:
        ip, _ = pool.next()
    if cfg["js"] == "off":
        # No JS: a plain HTTP client. No fingerprint, no behavior telemetry.
        fp, behavior, ua, langs = None, None, UA["chrome_win"], ["en-US", "en"]
    else:
        fp, ua_key, locale = _pick_consistent(rng)
        fp = dict(fp)
        ua, langs = UA[ua_key], locale[1]
        behavior = (_humanized_behavior(rng) if cfg["behavior"] == "humanized"
                    else _scripted_behavior(rng))
    headers = browser_headers(langs) if cfg["lang"] == "present" else {}
    if cfg["lang"] == "absent":
        headers = {}                       # no Accept-Language at all
    think = human_think(6.0) if cfg["behavior"] == "humanized" else fixed_think(0.8)
    return Persona(actor=actor, cohort=cohort, is_bot=True, ip=ip, user_agent=ua,
                   headers=headers, fp=fp, behavior=behavior, think=think,
                   browse=cfg["browse"], loads_assets=(cfg["assets"] == "load"),
                   honeypot=0.0, usd_per_gb=pool.usd_per_gb, config=dict(cfg))


def _pick_consistent(rng):
    inv = inventory(rng)
    return rng.choice(inv)


def _scripted_behavior(rng):
    """What page.click()/page.fill() produce: almost nothing (W2 Ch1)."""
    moves = rng.randint(0, 4)
    return {"mouse_moves": moves, "straightness": 1.0 if moves else None,
            "speed_cv": round(rng.uniform(0.0, 0.05), 3) if moves else None,
            "clicks": rng.randint(2, 3), "keys": 0, "key_cv": None,
            "touches": 0, "scrolls": 0, "first_input_ms": rng.randint(30, 120)}


def _humanized_behavior(rng):
    """A humanizer that is *almost* human. The attacker samples curved paths,
    jittered typing and scrolling — but from tighter distributions than real
    people (speed_cv, key_cv) and straighter paths. That residual regularity
    is the tell Round 2's adversarial training learns: on its own it is weak,
    but conditioned on an otherwise-human-looking session it carries signal.
    Real desktop users (tools/shopper.desktop_behavior) spread much wider."""
    keys = rng.choice([0, 0, rng.randint(5, 40)])
    return {"mouse_moves": int(rng.lognormvariate(5.6, 0.4)),
            "straightness": round(min(1.0, rng.betavariate(8, 2)), 3),
            "speed_cv": round(rng.uniform(0.30, 0.55), 3),
            "clicks": rng.randint(3, 10), "keys": keys,
            "key_cv": round(rng.uniform(0.18, 0.34), 3) if keys else None,
            "touches": 0, "scrolls": rng.randint(4, 30),
            "first_input_ms": int(rng.lognormvariate(7.1, 0.4))}


def verdict(result):
    """What the attacker reads from one checkout: 1 = blocked, 0 = allowed.

    This is the single bit a decision oracle unavoidably leaks: the site has
    to act on the verdict, so the attacker always learns it (polling the
    order if the answer is deferred). No score is echoed in this chapter.
    """
    if result["final"] in ("confirmed",):
        return 0
    if result["status"] == 200:
        return 0
    return 1


def coin(key):
    """Deterministic [0,1) hash of a string: stable randomness for replays."""
    return int(hashlib.sha256(str(key).encode()).hexdigest(), 16) % 10_000 / 10_000


def cost_rank(cfg):
    """Order configs cheapest-first for tie-breaking an evasion search."""
    return tuple(KNOBS[k].index(cfg[k]) for k in FEATURES)
