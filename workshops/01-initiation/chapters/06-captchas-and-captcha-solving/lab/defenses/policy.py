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

import os

BANDS = {"monitor": 20, "challenge": 40, "block": 75}

# The challenge type to serve when a check asks for a challenge without naming one.
# None in the W1 starter: the challenge band is enforced as a block until a chapter
# registers a type (W1 Ch6 captcha, W1 Ch7 proof of work, W2 Ch2 JS challenge). Ch6's checks
# name `captcha` themselves, so this stays None.
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


# --- Chapter 6: CAPTCHAs ------------------------------------------------------------------------

# Simulated time. LAB_TIME_SCALE=5 means one real second counts as five simulated seconds, so a
# 40-second farm solve takes 8 real seconds. Every threshold in solver_signals.py is in SIMULATED
# seconds. Lab-only: a real deployment has one clock.
TIME_SCALE = float(os.environ.get("LAB_TIME_SCALE", "5"))

# The mock provider's key pair (provider/mock_turnstile.py). They are TEST keys for a MOCK: nothing
# here talks to Cloudflare. Site keys are public by design (they ship in your HTML); the secret
# only ever lives on your server.
SITEKEY = "lab-sitekey-0000"
SECRET = os.environ.get("CAPTCHA_SECRET", "lab-secret-0000")
OUR_HOSTNAMES = {"localhost", "127.0.0.1"}        # the hostnames a token must have been solved on
TOKEN_FIELD = "cf-turnstile-response"             # the hidden input the widget adds to the form

# Per endpoint, on purpose: a provider outage stops sign-ups (closed) or lets a newsletter bomb in (open).
TURNSTILE_FAIL_MODE = {"register": "closed", "newsletter": "open"}

# Self-hosted image CAPTCHA (the `captcha` challenge type, on the promo voucher).
CAPTCHA_POINTS = 45                 # a captcha verdict needs >= BANDS["challenge"] to be served
CAPTCHA_TTL_SIM_S = 120             # simulated seconds an issued image stays valid
CAPTCHA_CLEARANCE_TTL = 120         # real seconds a solve clears the session (and uses=1: one redemption)
HARDENED_FROM_LEVEL = 3             # the image style: "basic" below this level, "hardened" from it
REDEEM_WINDOW_SIM_S = 600           # how long "this IP already redeemed" is remembered (Round 4)


def redeemed_key(ip):
    """Redis counter: promo vouchers redeemed from this IP lately (written by the promo route, read by Round 4)."""
    return f"lab:captcha:redeemed:ip:{ip}"
