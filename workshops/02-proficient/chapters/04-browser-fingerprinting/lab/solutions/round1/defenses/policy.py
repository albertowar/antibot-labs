"""
Policy: every number the defender tunes, and how a verdict becomes an HTTP answer.

pipeline.py decides WHICH checks run; this file decides HOW MUCH each signal
counts and WHERE the lines are. Chapters tune these values; W2 Ch8 replaces
decide() with calibrated weights; W3 Ch4 loads them from a hot-reloaded file.

One scale for every check: 0 (clean) to 100 (certain).

    score >= 40   block       403 (Chapter 4's bands; the starter's are 75 / 40 / 20)
    score >= 20   monitor     logged, served: the account is created ("suspicious")
    otherwise     allow       ("clean")

Every point you add to a signal moves some real users up a band too. The
scoreboard reports both sides; a change that catches one more bot and blocks
two shoppers is a regression.
"""

import os

# Chapter 4: 40 points refuse the sign-up, exactly as W1 Ch4's header engine does. There is no
# separate challenge band here (challenge == block, and decide() checks block first): a sign-up
# farm gets a 403. In production the middle of this scale is where a CAPTCHA or proof of work
# goes (W1 Ch6, Ch7), because a real person can still be one of the 40-point sign-ups.
BANDS = {"monitor": 20, "challenge": 40, "block": 40}

# How L3 and L4 (defenses/linking.py, fuzzy_cluster.py) decide how many accounts one device may
# create per day. "rarity" asks how many real visitors share the device class (rarity.py);
# "naive" treats every device as unique. Round 3 runs "naive" once to show who it hurts:
# edit this line (or LINK_MODE=naive in the store's environment), save, and re-run the shoppers.
LINK_MODE = os.environ.get("LINK_MODE", "rarity")

# Seconds a session's fingerprint record stays valid (defenses/fingerprint.py).
FP_TTL = 3600

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


def decide(score, signals, level):
    """Map a total score to a band. `signals` and `level` are here for chapters that override."""
    if score >= BANDS["block"]:
        return "block"
    if score >= BANDS["challenge"]:
        return "challenge"
    if score >= BANDS["monitor"]:
        return "monitor"
    return "allow"
