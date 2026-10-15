"""
Policy: every number the defender tunes, and how a verdict becomes an HTTP answer.

pipeline.py decides WHICH checks run; this file decides HOW MUCH each signal
counts and WHERE the lines are. Chapters tune these values; W2 Ch8 replaces
decide() with calibrated weights; W3 Ch4 loads them from a hot-reloaded file.

One scale for every check: 0 (clean) to 100 (certain).

    score >= 75   block       403 (a trap hit answers with a fake success instead)
    score >= 40   challenge   serve a registered challenge type, else a 403
    score >= 20   monitor     logged, served
    otherwise     allow

Every point you add to a signal moves some real users up a band too. The
scoreboard reports both sides; a change that catches one more bot and blocks
two shoppers is a regression.
"""

BANDS = {"monitor": 20, "challenge": 40, "block": 75}

# The challenge type to serve when a check asks for a challenge without naming one.
# None in the W1 starter: the challenge band is enforced as a block until a chapter
# registers a type (W1 Ch6 captcha, W1 Ch7 proof of work, W2 Ch2 JS challenge).
DEFAULT_CHALLENGE = None

# Seconds a cleared challenge stays valid for the session.
CLEARANCE_TTL = 15 * 60

# Token buckets: name -> (capacity, refill per second). Capacity is the burst you
# allow; refill is the sustained rate. Used by Ctx.bucket(name, key).
RATE_LIMITS = {
    "ip": (60, 2.0),
    "prefix": (200, 8.0),
    "login_ip": (10, 0.1),
    "checkout_ip": (12, 0.2),
}

# IP reputation points, by feed (data/feeds/*, W1 Ch3).
IP_POINTS = {
    "tor_exit": 40,
    "open_proxy": 40,
    "datacenter": 40,
    "hosting_asn": 25,
    "known_vpn": 40,
    "privacy_relay": 0,     # paying Safari customers, not bots
}


def decide(score, signals, level, ctx=None):
    """Map a total score to a band. `signals` and `level` are here for chapters that override;
    an override that declares `ctx` (or **kwargs) also receives the request's Ctx, so a policy
    can read per-request state (ctx.attrs, ctx.notes) without importing Flask (contract 1.7)."""
    if score >= BANDS["block"]:
        return "block"
    if score >= BANDS["challenge"]:
        return "challenge"
    if score >= BANDS["monitor"]:
        return "monitor"
    return "allow"
