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
# registers a type (W1 Ch5 captcha, W1 Ch6 proof of work, W2 Ch4 JS challenge).
DEFAULT_CHALLENGE = "otp"     # W3 Ch5: the emailed code (demo_site/ext/rba.py)

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


# --- W3 Ch5: risk-based authentication -------------------------------------------------------
#
# The score is a sum of log-likelihood ratios (defenses/rba_score.py): 0 means "as likely from the
# population as from this account", each +1 is e (~2.7) times more surprising for this account.
# tools/calibrate.py prints every cohort member's and attacker's score and band for these values.

RBA_ALPHA = 1.0                          # smoothing weight of the population prior in p(x | user)
RBA_REPUTATION = {"datacenter": 3.0}     # added log-odds for a network type (defenses/netinfo.py)
RBA_BANDS = {"medium": 0.0,              # score >= 0: unfamiliar, step up with an emailed code
             "high": 10.0}               # score >= 10: refuse (no prompt to farm or relay)
RBA_COLD_START = 5                       # fewer verified logins than this: never step down

FRICTION_BUDGET = 0.25                   # most of the sign-in cohort a round may prompt (the checkpoint's line)

COOLING_OFF_H = 72                       # Round 3: hours an unfamiliar-context password reset waits

