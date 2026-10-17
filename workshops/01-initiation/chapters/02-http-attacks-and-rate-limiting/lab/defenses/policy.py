"""
Policy: every number the defender tunes, and how a verdict becomes an HTTP answer.

pipeline.py decides WHICH checks run; this file decides HOW MUCH each signal
counts and WHERE the lines are. Chapters tune these values; W2 Ch8 replaces
decide() with calibrated weights; in production an ops team hot-reloads them from a config file.

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
# W1 Ch2: `ip` is 30 requests a minute (0.5/s) with a burst of 20 (Round 3). `login_ip` is the
# per-endpoint bucket (Round 4). `prefix` is per IPv4 /24 and loose (every home shopper here shares
# 192.0.2.0/24); `prefix6` is per IPv6 /64, one host's allocation, and tight (Round 5).
RATE_LIMITS = {
    "ip": (20, 0.5),
    "prefix": (300, 10.0),
    "prefix6": (15, 0.5),
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


def decide(score, signals, level):
    """Map a total score to a band. `signals` and `level` are here for chapters that override."""
    if score >= BANDS["block"]:
        return "block"
    if score >= BANDS["challenge"]:
        return "challenge"
    if score >= BANDS["monitor"]:
        return "monitor"
    return "allow"


# --- W1 Ch2: HTTP Attacks & Rate Limiting ------------------------------------------------------

# Round 1 (defenses/flood_monitor.py): more than `threshold` requests from one address in
# `window` seconds earns a `monitor` tag. Logged and served, never blocked.
FLOOD_MONITOR = (60, 60)            # (threshold, window seconds)
FLOOD_MONITOR_POINTS = 20           # the monitor band: logged, served

# Round 2 (defenses/fixed_window.py): `limit` requests per address per `window` seconds, in
# windows aligned to the clock (key = now // window). Short, so a lab run crosses a boundary.
FIXED_WINDOW = (20, 10)             # (limit, window seconds): 120 a minute on paper

# Round 3, alternative (defenses/sliding_window.py): the same idea without the boundary.
SLIDING_WINDOW = (30, 60)           # (limit, window seconds): 30 a minute, like RATE_LIMITS["ip"]

# Round 4 (defenses/endpoint_limit.py): which bucket each action spends, on top of `ip`.
ENDPOINT_LIMITS = {"login": "login_ip"}

# Round 4 (defenses/account_limit.py): login attempts per target account, any source.
ACCOUNT_LIMIT = (5, 900)            # (attempts, window seconds): 5 per 15 minutes
ACCOUNT_RETRY_AFTER = 60            # what the 429 tells the client; the window is the real wait

# Round 5 (defenses/trusted_proxy.py): weak evidence from a forged X-Forwarded-For.
XFF_POINTS = {"xff_mismatch": 10, "xff_internal_claim": 20}
