"""
Policy: every number the defender tunes, and how a verdict becomes an HTTP answer.

pipeline.py decides WHICH checks run; this file decides HOW MUCH each signal
counts and WHERE the lines are. Chapters tune these values; W2 Ch8 replaces
decide() with calibrated weights; in production an ops team hot-reloads them from a config file.

One scale for every check: 0 (clean) to 100 (certain).

    score >= 40   block       403 (W2 Ch3's bands; the starter's are 75 / 40 / 20)
    score >= 20   monitor     logged, served
    otherwise     allow

Every point you add to a signal moves some real users up a band too. The
scoreboard reports both sides; a change that catches one more bot and blocks
two shoppers is a regression.
"""

# Chapter 3: one TLS layer that disagrees (50 points) is enough to refuse the request, exactly as
# W1 Ch4's header engine does. There is no separate challenge band (challenge == block, and decide()
# checks block first): in production the middle of this scale is where a CAPTCHA or proof of work
# goes (W1 Ch5, Ch6), because a corporate-proxy employee scores 50 here too.
BANDS = {"monitor": 20, "challenge": 40, "block": 40}

# What each TLS layer (defenses/ja4_denylist, tls_family, h2_fingerprint, browser_proof) scores when
# it disagrees with the request. A missing fingerprint on a store that sits behind a TLS edge scores
# 100: the request skipped the edge.
TLS_POINTS = 50
NO_FINGERPRINT_POINTS = 100

# Round 4: GET paths that need an engine proof when the TLS says "browser" (prefix match, so
# /api/products/p001 is covered and /product/p001 is not). The home page is deliberately not
# protected: it is where the proof is earned.
PROOF_PATHS = ("/products", "/api/products")

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
