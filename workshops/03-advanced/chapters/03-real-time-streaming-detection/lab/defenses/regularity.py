"""
Round 3 defense (part A) — timing regularity with Welford's online variance

Humans are irregular: they pause to read, get distracted, move at varying
speed. Bots, even jittered ones, tend to space their requests more evenly. The
measure is the coefficient of variation (CV) of inter-request gaps: standard
deviation over mean. A low CV means a metronome.

We cannot store every gap and compute variance at the end — this is a stream.
Welford's algorithm keeps a running count, mean and sum-of-squared-deviations,
updating each in O(1) with perfect numerical stability (see features.py, where
the per-session state is folded). This module only reads the CV that update
produced and turns it into a score.

Where it fails: it needs enough events to be meaningful (MIN_GAPS). The
low-and-slow attacker in this same round sends one request per IP, so there is
never a second gap to measure — regularity stays silent and the cross-key
detector has to carry that case. And a bot that sleeps a random human-like
amount between requests pushes its CV up into the human range; that is the
Round 4 move.
"""

MIN_GAPS = 8        # need at least this many inter-arrival gaps to judge timing
CV_BOT = 0.10       # below this is machine-regular
CV_HUMAN = 0.40     # at or above this is comfortably human


def detect(event, feats, sketches, r):
    cv = feats["cv"]
    if cv is None or feats["w_n"] < MIN_GAPS:
        return 0.0, None

    # Lower CV -> higher score. Linear between CV_HUMAN (0) and 0 (1).
    soft = max(0.0, min(1.0, (CV_HUMAN - cv) / CV_HUMAN))
    if cv < CV_BOT:
        return soft, {
            "sid": event["sid"], "ip": event["ip"], "detector": "regularity",
            "signal": "timing_regularity", "cv": round(cv, 4), "gaps": feats["w_n"],
            "bot_score": round(min(1.0, (CV_BOT - cv) / CV_BOT + 0.5), 3),
            "action": "block", "ts": float(event["ts"]),
        }
    return soft, None
