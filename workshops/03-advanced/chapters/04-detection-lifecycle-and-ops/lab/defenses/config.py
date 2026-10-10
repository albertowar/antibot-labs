"""
Chapter 4 (W3): Operational configuration, hot-reloaded

Everything an operator may need to change in the middle of an incident lives
in one JSON file, ../data/ops_config.json, and the app re-reads it whenever
its mtime changes. No deploy, no restart:

    weights        {signal: points}   overrides for policy.WEIGHTS (0 = kill switch)
    challenge_at   int                the ladder's challenge line (policy.CHALLENGE_AT)
    block_at       int                the ladder's block line (policy.BLOCK_AT)
    campaign       bool               run the campaign layer (W2 Ch8 Round 4) and its step-up
    stepup_asn     int | null         blunt containment: step up every login from this ASN,
                                      real customers included (contain.py, Round 4)
    until_clock    int | null         lab-clock deadline: when it passes, the overrides above
                                      expire and the shipped policy is back (contain.py)
    canary_pct     int                share of sessions scored by the canary model
                                      (which model is prod/shadow/canary lives in registry.py)

Why a file and not a flag in code: a weight is a statement about trust that
changes faster than code ships. A kill switch that needs a deploy is not a
kill switch. Why a TTL: every containment measure you take at 02:00 is a
promise to undo it, and the TTL keeps the promise for you.

Trade-off: a hot config is also an attack surface and a footgun. In
production it belongs in a store with history and an audit log (who, when,
why), and a change should run against last week's traffic first
(tools/sweep.py in W2 Ch8; tools/ops.py --replay here).
"""

import json
import os
import threading

LAB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
CONFIG_PATH = os.environ.get("OPS_CONFIG", os.path.join(LAB, "data", "ops_config.json"))

DEFAULTS = {
    "weights": {},
    "challenge_at": None,
    "block_at": None,
    "campaign": False,
    "stepup_asn": None,
    "until_clock": None,
    "canary_pct": 0,
    "note": "",
}

_lock = threading.Lock()
_cache = {"mtime": None, "data": dict(DEFAULTS)}


def load():
    """Current config (defaults merged with the file), cached on mtime."""
    with _lock:
        try:
            mtime = os.path.getmtime(CONFIG_PATH)
        except OSError:
            _cache.update(mtime=None, data=dict(DEFAULTS))
            return dict(_cache["data"])
        if mtime != _cache["mtime"]:
            with open(CONFIG_PATH) as f:
                data = json.load(f)
            merged = dict(DEFAULTS)
            merged.update({k: v for k, v in data.items() if k in DEFAULTS})
            _cache.update(mtime=mtime, data=merged)
        return dict(_cache["data"])


def effective(clock=None):
    """Config with expired overrides removed. `clock` is the lab clock of the
    request being scored; a None deadline never expires."""
    cfg = load()
    until = cfg.get("until_clock")
    if until is not None and clock is not None and clock >= until:
        cfg.update(weights={}, challenge_at=None, block_at=None, campaign=False,
                   stepup_asn=None, until_clock=None, note=cfg.get("note", "") + " (expired)")
    return cfg


def update(**changes):
    """Write changes on top of the file (tools use this; the app only reads)."""
    with _lock:
        data = {}
        if os.path.exists(CONFIG_PATH):
            with open(CONFIG_PATH) as f:
                data = json.load(f)
        for key, value in changes.items():
            if key == "weights":
                data.setdefault("weights", {}).update(value)
                data["weights"] = {k: v for k, v in data["weights"].items() if v is not None}
            else:
                data[key] = value
        os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
        with open(CONFIG_PATH, "w") as f:
            json.dump(data, f, indent=2)
        _cache["mtime"] = None
    return data


def clear():
    with _lock:
        if os.path.exists(CONFIG_PATH):
            os.remove(CONFIG_PATH)
        _cache.update(mtime=None, data=dict(DEFAULTS))
