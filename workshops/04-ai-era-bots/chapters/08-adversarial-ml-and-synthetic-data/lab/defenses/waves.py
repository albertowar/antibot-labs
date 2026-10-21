"""
Waves: which traffic is in which training set.

The training history (data/history/, defenses/history.py) is one growing file. Every round of this
chapter appends a *wave* of traffic to it, and each model is trained on the waves that exist at its
stage. Tagging the waves makes that explicit and repeatable: retraining the Round 2 model next week,
after the Round 4 traffic has been logged, still gives the Round 2 model.

    drop     the drop day itself: 600 real customers + 300 baseline scalpers      (Round 0)
    evade    the red team's surrogate-guided evasion run                          (Round 2)
    poison   the privacy-lookalike honeypot burst                                  (Round 3)
    rare     the slow mobile reseller                                              (Round 4)

A session with no tag belongs to "drop". The tag file is data/history/waves.json, next to the log it
describes; it is generated and gitignored, like the rest of the history.

This is bookkeeping, not ground truth: it says WHEN a session was collected, never whether it was a
bot. A defender knows when a traffic spike arrived; only the simulator knows who sent it.
"""

import json
import os

from . import history

FILE = os.path.join(history.DIR, "waves.json")

# The waves each stage trains on: everything collected up to that stage.
STAGES = {
    "base": ("drop",),
    "robust": ("drop", "evade"),
    "sanitized": ("drop", "evade", "poison"),
    "augmented": ("drop", "evade", "poison", "rare"),
}


def load():
    """{sid: wave} for every tagged session."""
    if not os.path.exists(FILE):
        return {}
    with open(FILE) as fh:
        return json.load(fh)


def reset():
    if os.path.exists(FILE):
        os.remove(FILE)


def tag(sids, wave):
    """Record that these sessions were collected as `wave`. Existing tags are kept."""
    os.makedirs(history.DIR, exist_ok=True)
    tags = load()
    for sid in sids:
        tags.setdefault(sid, wave)
    with open(FILE, "w") as fh:
        json.dump(tags, fh)


def restrict(hist, waves):
    """The history `hist` (history.load()) reduced to the sessions collected in `waves`."""
    tags = load()
    keep = {r["sid"] for r in hist["events"] if tags.get(r["sid"], "drop") in waves}
    return {"events": [r for r in hist["events"] if r["sid"] in keep],
            "telemetry": [r for r in hist["telemetry"] if r["sid"] in keep],
            "logins": {s: a for s, a in hist["logins"].items() if s in keep},
            "accounts": hist["accounts"]}


def for_stage(stage):
    """history.load() restricted to what `stage` ('base', 'robust', 'sanitized', 'augmented') trains on."""
    return restrict(history.load(), STAGES[stage])


def sessions_in(hist, wave):
    """The sids of one wave."""
    tags = load()
    return {r["sid"] for r in hist["events"] if tags.get(r["sid"], "drop") == wave}
