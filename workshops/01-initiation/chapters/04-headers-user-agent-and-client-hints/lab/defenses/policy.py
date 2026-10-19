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

# Chapter 4: header evidence alone is not worth a challenge page. 40 blocks (as the original lab did),
# 20-39 is "suspicious": served, logged, and visible in the scoreboard's average score.
BANDS = {"monitor": 20, "challenge": 40, "block": 40}

# The challenge type to serve when a check asks for a challenge without naming one.
# None in the W1 starter: the challenge band is enforced as a block until a chapter
# registers a type (W1 Ch5 captcha, W1 Ch6 proof of work, W2 Ch4 JS challenge).
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


def decide(score, signals, level):
    """Map a total score to a band. `signals` and `level` are here for chapters that override."""
    if score >= BANDS["block"]:
        return "block"
    if score >= BANDS["challenge"]:
        return "challenge"
    if score >= BANDS["monitor"]:
        return "monitor"
    return "allow"


# --- Chapter 4 tunables: headers, User-Agent and Client Hints -----------------------------------
# Browsers auto-update, so anything far behind stable is mostly forged. "Far behind" is a judgement:
# raise the floor and you start catching real people who postpone updates (the old_chrome shopper
# runs Chrome 138). Bump both floors every quarter.
MIN_CHROME_MAJOR = 140
MIN_FIREFOX_MAJOR = 115          # the current Firefox ESR line
STALE_VERSION_POINTS = 20        # exercise: set it to 40 and watch old_chrome get blocked

# Round 4: Accept-CH asks Chromium for these on every following request to this origin.
ACCEPT_CH_HINTS = ("Sec-CH-UA-Full-Version-List", "Sec-CH-UA-Platform-Version", "Sec-CH-UA-Arch")
OFFERED_COOKIE = "ch_offered"    # "we asked for the hints": the server's memory of the negotiation

# Bonus challenge 3: Critical-CH makes Chromium retry the FIRST navigation with the hints, so the
# server no longer needs the cookie to know it asked. Flip it and read demo_site/ext/headers.py.
CRITICAL_CH = False
