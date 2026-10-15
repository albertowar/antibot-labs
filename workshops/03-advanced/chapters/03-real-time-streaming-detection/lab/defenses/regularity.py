"""
Round 3 defense (part A): timing regularity with Welford's online variance.

People are irregular: they pause to read, get distracted, move at varying speed. Bots, even
jittered ones, tend to space requests more evenly. The measure is the coefficient of variation
(CV) of inter-request gaps: standard deviation over mean. A low CV is a metronome.

We cannot store every gap and compute the variance at the end: this is a stream. Welford's
algorithm keeps a running count, mean and sum of squared deviations, updating each in O(1) with
good numerical stability (features.py folds it into the session hash). This module only reads the
CV that update produced and turns it into a score. CV is scale-free, so the lab's short windows
do not change it.

Where it fails: it needs enough events to mean anything (MIN_GAPS). The low-and-slow attacker
makes one request per IP, so there is never a second gap to measure and this detector stays
silent. A bot that sleeps a random human-like time between requests pushes its CV into the human
range (Round 4).

Who it hurts: an assistive tool or a kiosk that clicks at a steady pace, and a person who simply
mashes reload. Keep CV_BOT low and the MIN_GAPS high, and flag the session, not the IP.
"""

from . import streamlog
from .pipeline import Check

MIN_GAPS = 8        # need at least this many inter-arrival gaps to judge timing
CV_BOT = 0.10       # below this is machine-regular
CV_HUMAN = 0.40     # at or above this is comfortably human


def detect(event, feats, sketches, softs, r):
    cv = feats["cv"]
    if cv is None or feats["w_n"] < MIN_GAPS:
        return 0.0, None
    soft = max(0.0, min(1.0, (CV_HUMAN - cv) / CV_HUMAN))
    if cv < CV_BOT:
        return soft, {
            "sid": event["sid"], "ip": event["ip"], "detector": "regularity", "signal": "timing_regularity",
            "subject": ("sid", event["sid"]), "cv": round(cv, 4), "gaps": feats["w_n"],
            "bot_score": round(min(1.0, (CV_BOT - cv) / CV_BOT + 0.75), 3), "action": "block",
            "ts": float(event["ts"]),
        }
    return soft, None


CHECK = Check("regularity", streamlog.enforcer("regularity", ("sid",)))
