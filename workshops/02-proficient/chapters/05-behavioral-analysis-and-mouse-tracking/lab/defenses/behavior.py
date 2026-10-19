"""
Chapter 5: the glue between the behavior layers and the store's gate.

The drop page (demo_site/ext/templates/drop.html) draws the reservation form at
fixed positions inside #behavior-form, and static/js/behavior.js records how it
was filled in. Just before the form is submitted, the page posts that record to
POST /api/telemetry {"kind": "behavior", ...}. When the form arrives at
POST /drop/<sku>, the route calls guard("drop_buy"), and every behavior_lN
check in defenses/ladder.py reads the same features from here.

    layout       where the server drew each box for THIS session (ctx.session),
                 shifted by the form's page offset the collector reports
    features     behavior_features.extract(), computed once per request
    signals      a layer's (points, name, reason) hits as pipeline Signals

Trade-off: the form's page offset (`origin`) comes from the client, like every
other number in the payload. That is fine for Layers 1-3, which only look at
shapes and timings. Layer 4's "click outside its target" rule compares the
clicks with the layout the server chose for this session; a forger who reuses
an old payload keeps the old clicks, so they miss the new boxes. A forger who
rewrites the payload for every session is the warped replay of Round 4.
"""

import json
import random

from .behavior_features import extract
from .pipeline import Signal

TELEMETRY_KIND = "behavior"
LAYOUT_KEY = "behavior_layout"           # session hash field: this session's boxes (form-relative)
SIGS_KEY = "lab:behavior:signatures"     # Layer 4 memory: the last MAX_SIGS sessions' signatures
TRACES_KEY = "lab:behavior:trace:"       # + sid: the raw record, for the viewer and save_trace.py
RECENT_KEY = "lab:behavior:recent"       # newest sids first
MAX_SIGS = 2000
MAX_RECENT = 500

# Form-relative boxes [x, y, w, h] in CSS pixels. Every element is absolutely
# positioned with a fixed size, so the server knows where each box is drawn.
FIELDS = {"name": (0, 0, 300, 40), "email": (0, 64, 300, 40), "size": (0, 128, 110, 40)}
BUTTON = (0, 200, 150, 48)
BASE = (20, 110)                          # where the form sits when nothing moves it
FORM_SIZE = (360, 370)                    # the #behavior-form box the page reserves


def new_layout(level, rng=random):
    """
    Where to draw the form for one page view.

    Below Level 4 the layout never changes. From Level 4 on (layout jitter) the
    whole form moves up by 45-90 px and the button slides sideways: a recorded
    trace that clicked the fields last time now clicks empty page. Real users do
    not notice; a replay has to read the page and adapt. The move is at least
    45 px, more than a field's height, so a payload recorded on the un-jittered
    page always misses. It only ever moves up, so the button stays inside a
    720 px-tall window.
    """
    ox, oy = BASE
    bx = 0
    if level >= 4:
        ox = rng.randint(0, 40)
        oy = BASE[1] - rng.randint(45, 90)
        bx = rng.randint(0, 140)
    boxes = {name: [ox + x, oy + y, w, h] for name, (x, y, w, h) in FIELDS.items()}
    x, y, w, h = BUTTON
    boxes["reserve"] = [ox + bx + x, oy + y, w, h]
    return {"boxes": boxes, "form": list(FORM_SIZE)}


def page_layout(rel, telemetry):
    """Form-relative boxes -> page boxes, using the form's page offset the collector saw."""
    ox, oy = (telemetry or {}).get("origin") or [0, 0]
    return {"origin": [ox, oy], "boxes": {k: [ox + b[0], oy + b[1], b[2], b[3]] for k, b in rel["boxes"].items()}}


def session_layout(ctx):
    raw = ctx.session.get(LAYOUT_KEY)
    return json.loads(raw) if raw else None


def features(ctx):
    """This request's behavior features, or None when the session posted no telemetry."""
    if "behavior" not in ctx.attrs:
        telemetry, rel = ctx.telemetry(TELEMETRY_KIND), session_layout(ctx)
        if not telemetry or not rel:
            ctx.attrs["behavior"] = None
        else:
            ctx.attrs["behavior"] = extract(telemetry, page_layout(rel, telemetry))
    return ctx.attrs["behavior"]


def signals(layer, hits):
    """[(points, name, reason)] -> Signals for the pipeline (the reason goes to the decision log)."""
    return [Signal(f"behavior_{layer}", name, points, reason) for points, name, reason in hits]


def recent_signatures(redis, exclude_sid):
    out = []
    for raw in redis.lrange(SIGS_KEY, 0, MAX_SIGS - 1):
        item = json.loads(raw)
        if item["sid"] != exclude_sid:
            out.append((item["sid"], item["sig"]))
    return out


def remember(redis, sid, telemetry, rel, level, nbytes):
    """Store the raw record (viewer, save_trace.py) and its signature (Layer 4), at every level."""
    layout = page_layout(rel, telemetry)
    feats = extract(telemetry, layout)
    redis.lpush(SIGS_KEY, json.dumps({"sid": sid, "sig": feats["signature"]}))
    redis.ltrim(SIGS_KEY, 0, MAX_SIGS - 1)
    redis.set(TRACES_KEY + sid, json.dumps({"sid": sid, "level": level, "layout": layout, "telemetry": telemetry,
                                            "bytes": nbytes}), ex=24 * 3600)
    redis.lrem(RECENT_KEY, 0, sid)
    redis.lpush(RECENT_KEY, sid)
    redis.ltrim(RECENT_KEY, 0, MAX_RECENT - 1)
    return feats


def score_offline(trace, level):
    """
    Score a saved trace without a server (tools/score_trace.py, the checkpoint).
    Layer 4 is skipped: replay detection needs the server's memory of other sessions.
    Returns (score, reasons, verdict).
    """
    from . import behavior_l1, behavior_l2, behavior_l3, behavior_l5, policy
    feats = extract(trace["telemetry"], trace["layout"])
    layers = [(1, behavior_l1.score_presence), (2, behavior_l2.score_kinematics),
              (3, behavior_l3.score_motor), (5, behavior_l5.score_touch)]
    score, reasons = 0, []
    for n, fn in layers:
        if n <= level:
            for points, _, reason in fn(feats):
                score += points
                reasons.append(f"[L{n}] {reason}")
    score = min(100, score)
    bands = policy.BANDS
    verdict = "block" if score >= bands["block"] else "challenge" if score >= bands["challenge"] else "allow"
    return score, reasons, verdict
