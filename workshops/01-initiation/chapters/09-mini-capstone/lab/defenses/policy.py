"""
Policy: every number the defender tunes on Drop Day, and how a verdict becomes an HTTP answer.

ladder.py decides WHICH checks run at which level; this file decides HOW MUCH each signal counts
and WHERE the lines are. Drop Day is a policy-only exercise: edit THIS file and nothing else.

One scale for every check: 0 (clean) to 100 (certain).

    score >= 75   block       403 (a trap hit answers with a fake success instead)
    score >= 40   challenge   a proof of work from Round 4; before that there is nothing to serve, so a block
    score >= 20   monitor     logged, served
    otherwise     allow

Every point you add to a signal moves some real users up a band too. The scoreboard reports both
sides (hoodies the bots got, shoppers stopped, shoppers slowed); a change that catches one more bot
and stops two shoppers is a regression.

Each section names the chapter that introduced it. The modules that read these values are copies of
the finished versions from those chapters (see shared.json); only the numbers are the capstone's.
"""

BANDS = {"monitor": 20, "challenge": 40, "block": 75}

# The challenge type a "challenge" verdict serves: the W1 Ch6 proof of work (demo_site/ext/pow.py).
DEFAULT_CHALLENGE = "pow"

# Rounds 1-3 have nothing to serve in the challenge band, so decide() enforces it as a block. That is
# the cost Round 2 makes visible (a VPN shopper scores 40 and is stopped). From this level on, the
# same score earns a proof of work instead.
CHALLENGE_FROM_LEVEL = 4

# Seconds one solved proof of work clears the session (pow_budget.py shortens and limits it).
CLEARANCE_TTL = 10 * 60


def _answering_a_challenge():
    """True while the request in flight is a client delivering a challenge answer (or asking for one)."""
    from flask import has_request_context, request
    return has_request_context() and request.path.startswith("/api/challenge")


def decide(score, signals, level):
    """
    Map a total score to a band.

    Two capstone rules live here, because they are about what a verdict MEANS rather than how many
    points it earned:
      - until Round 4 nothing can be served in the challenge band, so it is a block;
      - the challenge endpoints are never themselves challenged. A visitor whose address scores 40 on
        EVERY page (a VPN) would otherwise be told to solve a puzzle and be refused when they deliver
        the answer: a challenge band that is a block in disguise. (A block, 75+, still blocks.)
    """
    if score >= BANDS["block"]:
        return "block"
    if score >= BANDS["challenge"]:
        if level < CHALLENGE_FROM_LEVEL:
            return "block"
        return "monitor" if _answering_a_challenge() else "challenge"
    if score >= BANDS["monitor"]:
        return "monitor"
    return "allow"


# --- Round 1 -- W1 Ch2 / Ch3: rate limits and "which IP?" ---------------------------------------------
# name: (capacity, refill tokens per second). Capacity is the burst you allow; refill is the sustained
# rate. A shared IP (carrier NAT, offices, universities) spends ONE bucket for everyone behind it, so
# per-IP buckets must stay loose. `ip` is every request; `prefix` is every request from one IPv4 /24
# (every home shopper sits in 192.0.2.0/24), `prefix6` one IPv6 /64 (one host's allocation: tight);
# `checkout_ip` is POST /drop/<sku> (drop_guard.py spends it; Ch2's own rate_limit only meters /checkout).
RATE_LIMITS = {
    "ip": (60, 2.0),
    "prefix": (200, 8.0),
    "prefix6": (15, 0.5),
    "login_ip": (10, 0.1),
    "checkout_ip": (12, 0.2),
}

# A forged X-Forwarded-For is weak evidence: honest clients behind proxies send one too.
XFF_POINTS = {"xff_mismatch": 10, "xff_internal_claim": 20}

# --- Round 1 -- W1 Ch4: headers ---------------------------------------------------------------------------
# A lone library User-Agent is 40, a missing Accept-Language 15, `Accept: */*` 10 (they live in the Ch4
# modules). python-requests with its defaults: 40 + 15 + 10 = 65, a "challenge" that is a block until Round 4.
MIN_CHROME_MAJOR = 140
MIN_FIREFOX_MAJOR = 115          # the current Firefox ESR line
STALE_VERSION_POINTS = 20        # exercise: set it to 40 and watch old_chrome get stopped

# --- Round 2 -- W1 Ch3: IP reputation --------------------------------------------------------------------
IP_POINTS = {
    "tor_exit": 40,
    "open_proxy": 40,
    "datacenter": 40,       # inside a published cloud range
    "hosting_asn": 25,      # the ASN is a hosting company
    "known_vpn": 40,        # commercial and corporate VPN egress ranges
    "privacy_relay": 0,     # paying Safari customers, not bots
}
# Private Relay egresses from datacenter ranges that the community VPN list also carries. True lets a
# relay hit cancel datacenter, hosting_asn and known_vpn (W1 Ch3's blue step); False stops both relay shoppers.
TRUST_PRIVACY_RELAYS = True

# --- Round 3 -- W1 Ch8: the session as evidence (drop_guard.SESSION_CHECK) --------------------------------
# no_landing        the session never loaded "/": nobody saw the store
# no_js_cookie      the page script never ran here. 25 is "monitor": a no-JS human is logged, not stopped
#                   (Ch8 ships 40 and makes you lower it; the capstone starts from the lowered value)
# session_too_young the buy came sooner than MIN_SESSION_SECONDS after the session began
SESSION_POINTS = {
    "no_landing": 30,
    "no_js_cookie": 25,
    "session_too_young": 20,
    "ua_changed": 50,       # Round 4 (binding): the browser identity changed since the session began
    "asn_changed": 20,      # Round 4 (binding): the session moved to a different network (a phone leaving Wi-Fi)
}
MIN_SESSION_SECONDS = 1.0   # autofill + a fast human finish a one-field form in ~1.5 s

# --- Round 3 -- W1 Ch7: traps -------------------------------------------------------------------------------
# A hit that answers with a hard verdict (a fake success) carries TRAP_HARD_POINTS; a logged-only hit
# (the trap link, a sanctioned client's later requests) stays in the monitor band.
TRAP_HARD_POINTS = 100
TRAP_MONITOR_POINTS = 30
MIN_FILL_SECONDS = 1.0       # a drop form submitted faster than this was not typed (below the autofill shopper's 1.2 s)
MAX_FORM_AGE = 2 * 3600      # an older timing token is a tab someone left open: not a trap
# What a client that tripped a trap gets from Round 4 on, and who the sanction is keyed on. "fake": the
# bot is told it bought. "session" because "ip" would stop every person behind a carrier-NAT address.
TRAP_RESPONSE_MODE = "fake"
TRAP_SANCTION_KEY = "session"
SANCTION_TTL = 15 * 60

# --- Round 4 -- W1 Ch6: proof of work ------------------------------------------------------------------------
# Pages behind the gate: the drop page and the JSON buy. Everything else stays free (a wall in front of
# the whole store prices people, not scalpers).
POW_PROTECTED = ("/drop/", "/api/buy")
POW_GATE_POINTS = 40         # lands in the challenge band by itself
POW_BASE_BITS = 16           # expected work is 2**bits hashes: each bit doubles it, for every shopper too.
                             # The price when nothing sets one; at level 4 pow_adaptive sets it from POW_ADAPTIVE below
POW_PASS_BUDGET = 20         # one solve buys this many protected requests ...
POW_PASS_TTL = 120           # ... or this many seconds, bound to the IP + User-Agent that solved it
# Adaptive difficulty (pow_adaptive.py): (max gated requests per window from one IP, bits); the last row
# catches the rest, and the FIRST row is the everyday price. Sized so a carrier-NAT address shared by
# eight phones stays at the base price. Drop Day: every bit doubles the work for a budget phone first.
POW_RATE_WINDOW_S = 60
POW_ADAPTIVE = [(40, 16), (80, 20), (None, 22)]

# --- Round 4 -- the capstone's own rule: one hoodie per customer ---------------------------------------------
# A session that has bought this many may not buy again (drop_guard.CAP_CHECK). None = no cap.
PURCHASES_PER_SESSION = 1
