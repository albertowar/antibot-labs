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



# --- W3 Ch6: session trust and sensitive actions ----------------------------------------------
#
# Trust is a number from 0 to 100 that a session carries after the login. A sensitive action has a
# weight on the same scale; the session may do it when trust >= weight, and otherwise has to earn
# more with a step-up factor or fall back to restricted mode. Time never raises trust.

# The lab clock. A lab second stands for LAB_CLOCK_DIVISOR real seconds, so NIST SP 800-63B-4's AAL2
# reauthentication limits (24 h overall, 1 h inactivity; both SHOULD) fit in a round that lasts
# minutes. POST /lab/clock {"advance_s": N} moves the clock (a tool's way of "waiting").
LAB_CLOCK_DIVISOR = 120
TRUST_AGE_LIMIT_S = 24 * 3600 / LAB_CLOCK_DIVISOR     # 720 lab s: login trust reaches 0 at the overall limit
TRUST_IDLE_LIMIT_S = 3600 / LAB_CLOCK_DIVISOR         # 30 lab s: ... and at the inactivity limit
FACTOR_TTL_S = 7200 / LAB_CLOCK_DIVISOR               # 60 lab s: a solved step-up counts for "two hours" (GitHub's sudo window)
TRUST_AGE_BONUS_PER_MIN = 0.0                         # the bug of Lesson 2 if non-zero: never raise trust with time

# What the session starts with, from the Chapter 5 login band (the ext stamps it; see session_trust.py).
LOGIN_TRUST = {"familiar": 70,       # low band, known device and known network
               "device_only": 45,    # low band carried by the remembered-device cookie alone
               "emailed_code": 55,   # medium band, emailed code solved
               "cold_start": 40}     # fewer than RBA_COLD_START verified logins
DRIFT_PENALTY = {"asn": 20, "ua": 25}  # in-session drift against the network and browser the session started on

# Action weights: the trust a session needs. 0 (or absent): no extra proof.
ACTION_RISK = {"address_add": 50, "card_add": 60, "gift_card_redeem": 60, "change_email": 75, "change_password": 75}
CHECKOUT_NEW_ADDRESS = 60            # an order shipped to an address that is not on file
CHECKOUT_NEW_CARD = 60               # an order paid with a card that is not the saved one
MASK_BELOW = 50                      # restricted mode: below this trust the account page is masked

# Step-up factors and the trust each can lift a session to. Round 3 onward; Round 2 uses a first
# model in session_trust.py that treats any second factor as strong. The numbers are lab choices:
# the ordering is the lesson (see Chapter 6 section 6.4), not the digits.
FACTOR_STRENGTH = {"sudo": 55,            # password re-entry: whoever has the password has it
                   "otp_session": 55,     # code to the on-file email: NIST does not accept email as out-of-band
                   "kba": 65,             # questions about the store's own data: readable by the asking session
                   "sms_otp": 80,         # code to the on-file phone (fictional 555-01xx numbers)
                   "device_confirm": 90}  # approve, with number matching, on a device the store already knows
KBA_STRENGTH_R4 = 40                 # Round 4 demotes KBA to a signal: it cannot lift a session to any weight

# Holds (Round 4): lab hours the change waits, by weight.
HOLD_HOURS = {60: 12, 75: 24}
NOTIFY_CHANNELS = ("email", "sms", "device", "banner")
