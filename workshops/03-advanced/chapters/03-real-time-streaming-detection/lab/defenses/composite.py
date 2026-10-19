"""
Round 4 defense: a composite streaming verdict with a global campaign term.

The attacker's last move is to look human from every single angle: one IP per session (beats
the window), page views (beats the stuffing-shape gate), jittered timing in the human range
(beats regularity), usernames rotated so no one account fans out (beats the cross-key join).
Each detector now sees only a weak signal, and none of them fires.

The composite combines the weak signals the way W2 Ch8 combined layers, with one addition that
only a stream gives you cheaply: the *global campaign context*. A session that failed two logins
is unremarkable on a quiet day. The same two failures on top of a global failed-login velocity
(or IP fan-out) far past normal are part of a campaign. The campaign term is the product of "this
session is failing logins" and "a campaign is happening right now": both must hold, so a person
mistyping a password in a quiet hour scores near zero while the same shape during an attack
scores high. The other terms are the soft scores the detectors kept per session.

Honesty: this does not catch everything. A patient attacker who keeps every term low (one failure
per session, well under the global velocity, no account fan-out) stays below the line; that
residual is real, and it is the hand-off to W3 Ch8 (monitoring, drift, retraining). And if the
consumer falls behind the stream (tools/lag.py), the verdict arrives after the attacker is done:
the latency gap, reopened.

Who it hurts: a person who fails two logins while a campaign is live. The composite's `challenge`
band has no challenge type registered in this lab, so it is enforced as a block and the cost
shows up in the shoppers' column; in production it would be a step-up.
"""

from . import streamlog
from .heavy_hitters import FANOUT_THRESHOLD, VELOCITY_THRESHOLD
from .pipeline import Check

WEIGHTS = {"campaign": 0.45, "cross_key": 0.25, "regularity": 0.15, "window_rate": 0.15}
BLOCK = 0.70
CHALLENGE = 0.40
MONITOR = 0.25


def _campaign_term(feats, sketches, event):
    """Product of session-level failing and a live global campaign. 0 for people."""
    if feats["n_fail"] < 2:
        return 0.0
    ts = float(event["ts"])
    velocity = sketches.endpoint_fail_rate("/api/login", ts)
    fanout = sketches.distinct_fail_ips(ts)
    session_term = min(1.0, feats["n_fail"] / 2.0)
    global_term = min(1.0, max(velocity / VELOCITY_THRESHOLD, fanout / FANOUT_THRESHOLD))
    return session_term * global_term


def action_for(score):
    if score >= BLOCK:
        return "block"
    if score >= CHALLENGE:
        return "challenge"
    if score >= MONITOR:
        return "monitor"
    return "allow"


def detect(event, feats, sketches, softs, r):
    terms = {
        "campaign": _campaign_term(feats, sketches, event),
        "cross_key": float(softs.get("cross_key", 0.0)),
        "regularity": float(softs.get("regularity", 0.0)),
        "window_rate": float(softs.get("window_rate", 0.0)),
    }
    score = round(sum(WEIGHTS[k] * v for k, v in terms.items()), 3)
    action = action_for(score)
    if action in ("challenge", "block"):
        return score, {
            "sid": event["sid"], "ip": event["ip"], "detector": "composite", "signal": "composite",
            "subject": ("sid", event["sid"]), "terms": {k: round(v, 3) for k, v in terms.items()},
            "bot_score": score, "action": action, "ts": float(event["ts"]),
        }
    return score, None


CHECK = Check("composite", streamlog.enforcer("composite", ("sid",)))
