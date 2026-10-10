"""
Round 4 defense — composite streaming verdict

The attacker's last move is to look human from every single angle: spread
across IPs (beats the window), rotate usernames so no one account fans out
(beats the cross-key join), jitter the timing into the human range (beats
regularity), and load a couple of assets (beats the stuffing-shape gate). Each
detector now sees only a weak signal. No one of them fires.

The composite combines the weak signals the way W2 Ch8 combined layers, with
one addition that only a stream gives you cheaply: the *global campaign
context*. A session that failed two logins is unremarkable on a quiet day. The
same two failures, sitting on top of a global failed-login velocity of
hundreds across the whole stream, are part of a campaign. The campaign term is
the product of "this session is failing logins" and "a campaign is happening
right now" — both must hold, so a human mistyping a password during quiet
times scores near zero while the same shape during an attack scores high.

Honesty: this does not catch everything. A patient attacker who keeps every
term low — a trickle of failures, well under the global velocity, no account
fan-out — stays below the line. That residual is real. It is why the next
chapter (W3 Ch4) watches these signals decay over time and why longer windows
and account-side controls (W2 Ch6) still matter. And if the consumer falls
behind the stream (tools/lag.py), the verdict arrives after the attacker is
done — the latency gap, reopened.
"""

from heavy_hitters import VELOCITY_THRESHOLD, FANOUT_THRESHOLD

WEIGHTS = {"campaign": 0.45, "cross_key": 0.25, "regularity": 0.15, "window_rate": 0.15}
BLOCK = 0.70
CHALLENGE = 0.40
MONITOR = 0.25


def _campaign_term(feats, sketches, event):
    """Product of session-level failing and a live global campaign. 0 for humans."""
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
        "cross_key": softs.get("cross_key", 0.0),
        "regularity": softs.get("regularity", 0.0),
        "window_rate": softs.get("window_rate", 0.0),
    }
    score = round(sum(WEIGHTS[k] * v for k, v in terms.items()), 3)
    action = action_for(score)
    if action in ("challenge", "block"):
        return score, {
            "sid": event["sid"], "ip": event["ip"], "detector": "composite",
            "signal": "composite", "terms": {k: round(v, 3) for k, v in terms.items()},
            "bot_score": score, "action": action, "ts": float(event["ts"]),
        }
    return score, None
