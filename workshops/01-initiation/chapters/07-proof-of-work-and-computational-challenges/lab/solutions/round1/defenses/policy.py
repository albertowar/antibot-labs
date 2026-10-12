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
# W1 Ch7 registers the "pow" type (demo_site/ext/pow.py), so the challenge band serves it.
DEFAULT_CHALLENGE = "pow"

# Seconds a cleared challenge stays valid for the session. W1 Ch7: the L1-L2 "pass" lasts
# 10 minutes and has no request budget; defenses/pow_budget.py shortens and limits it from L3.
CLEARANCE_TTL = 10 * 60

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


# --- W1 Ch7: proof of work -------------------------------------------------------
# Every number the PoW defender tunes. Read the trade-off next to each one.

# Pages that cost money to serve and are worth scraping. Everything else stays free:
# a PoW wall in front of /login or /checkout prices people, not scrapers (see Bonus 2).
POW_PROTECTED = ("/products", "/catalog", "/product/", "/api/products", "/search", "/api/search")

# Points the gate adds when a client has no pass. 40 lands in the `challenge` band alone.
POW_GATE_POINTS = 40

# Difficulty in leading zero bits: expected work is 2**bits hashes. Each bit doubles it.
POW_BASE_BITS = 16

# L3: one solve buys this many protected requests or this many seconds, whichever ends first.
POW_PASS_BUDGET = 20
POW_PASS_TTL = 120

# L4: adaptive difficulty. (max requests in the window, bits); the last row catches the rest.
# The window counts every gated request from the client key, not only catalog pages. A person
# browsing stays under 10 a minute; a carrier-NAT address shared by 4,000 people does not.
POW_RATE_WINDOW_S = 60
POW_ADAPTIVE = [(10, 16), (20, 20), (None, 22)]
