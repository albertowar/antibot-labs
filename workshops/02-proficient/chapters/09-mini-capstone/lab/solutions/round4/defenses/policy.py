"""
Round 4 reference policy (the catch-up file; the numbers are the same in every round, so this restores
the shipped tuning after an experiment). The live file is defenses/policy.py.

Policy: every number the defender tunes, and how a verdict becomes an HTTP answer.

pipeline.py decides WHICH checks run; this file decides HOW MUCH each signal counts and WHERE the
lines are. The capstone composes finished checks from Chapters 1, 3, 4, 5 and 6 (shared.json), and
every one of them reads its numbers from here: the names below are exactly the ones those copies ask
for, so a check keeps working unedited and the capstone's tuning happens in ONE file.

One scale for every check: 0 (clean) to 100 (certain). Chapter 5's bands, because behavior and
account evidence is probabilistic: a challenge costs a real customer a few seconds, a block costs
them the pair.

    score >= 60   block       403
    score >= 30   challenge   serve the "proof" challenge (a small proof of work), else a 403
    score >= 15   monitor     logged, served
    otherwise     allow

Each request phase decides on its OWN signals: the request phase (headers, TLS) decides on every
request; the drop phase (`action:drop_buy`) decides on the buy and does not inherit the request
phase's points; the login phase decides on the login. Read defenses/ladder.py for who runs where.
"""

BANDS = {"monitor": 15, "challenge": 30, "block": 60}

# The challenge type to serve when a check asks for a challenge without naming one. "proof" is the
# capstone's own (demo_site/ext/drop9.py): a hashcash a browser solves in well under a second. Without
# a registered type the challenge band would be enforced as a block, which is what the earlier
# chapters' labs show; here a real customer in the band pays a second of CPU instead of losing the pair.
DEFAULT_CHALLENGE = "proof"
PROOF_BITS = 12                    # ~4k SHA-256 attempts on average
CLEARANCE_TTL = 15 * 60

# Token buckets: name -> (capacity, refill per second). Used by Ctx.bucket(name, key).
RATE_LIMITS = {
    "ip": (60, 2.0),
    "prefix": (200, 8.0),
    "login_ip": (10, 0.1),
    "checkout_ip": (12, 0.2),
}

IP_POINTS = {
    "tor_exit": 40, "open_proxy": 40, "datacenter": 40, "hosting_asn": 25, "known_vpn": 40,
    "privacy_relay": 0,
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


# --- Chapter 1: header rules (ua_inspector) and the sensor (sensor, sensor_gate) ------------------
MIN_CHROME_MAJOR = 140
MIN_FIREFOX_MAJOR = 115
STALE_VERSION_POINTS = 20          # a customer who postpones updates is not a bot

SENSOR_TTL = 10 * 60               # a sensor report counts for this long (page load -> the buy)
NONCE_TTL = 2 * 60                 # a page's sensor nonce must be used within this long, once
# What needs a sensor report. The drop is bought with a form POST to /drop/<sku> or a JSON POST to
# /api/buy; defenses/drop_guard.py runs the sensor checks in the action:drop_buy phase only, so the
# drop PAGE (where the sensor runs) is never gated by its own report.
SENSOR_GATED = ("/drop/lab-runner-9", "/api/buy")
NO_SENSOR_POINTS = 60              # no report at all: JavaScript off or never ran. A block, as in Chapter 1.

# --- Chapter 3: TLS (ja4_denylist, tls_family) ---------------------------------------------------
# The store sees a CLAIMED JA4 (X-Lab-JA4): each simulated client sends what its real TLS stack puts
# on the wire (defenses/known_fingerprints.json). A missing one means the request skipped the edge.
TLS_POINTS = 50
NO_FINGERPRINT_POINTS = 100

# --- Round 2: flow (defenses/flow.py) ------------------------------------------------------------
MIN_DWELL_MS = 2500                # the server's own clock: page served -> buy (a person fills three fields in more)
DWELL_POINTS = 30
COLD_BUY_POINTS = 40               # a buy with no view of the drop page in this session

# --- Round 3: the session and account model (defenses/session_model.py) --------------------------
MODEL_MAX_FPR = 0.01               # the false-positive budget the threshold is picked from
MODEL_BLOCK_POINTS = 60            # p(bot) at or above the threshold
MODEL_CHALLENGE_POINTS = 30        # above half the threshold

# --- Round 4: login token and failures per fingerprint cluster -----------------------------------
TOKEN_BITS = 14                    # proof of work bound to the session and the fingerprint hash
TOKEN_TTL_S = 120
NO_TOKEN_POINTS = 60
CLUSTER_WINDOW_S = 600
CLUSTER_MIN_FAILURES = 5
CLUSTER_MAX_FAILURE_RATIO = 0.5
CLUSTER_POINTS = 60
CAMPAIGN_MIN_FAILURES = 10         # the family-wide trip comes later than one cluster's: the family holds real users
CAMPAIGN_FAILURE_RATIO = 0.5
CAMPAIGN_POINTS = 30               # challenge band, never block: see login_risk.py on who shares the family
