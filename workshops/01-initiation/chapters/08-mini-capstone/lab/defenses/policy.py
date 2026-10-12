"""
W1 Ch8 — Policy: every number the defender tunes (Section 8.2).

pipeline.py decides WHICH layers run. This file decides HOW MUCH each signal
counts and WHERE the lines are. On Drop Day this is the only file you edit.

One scale for every layer: 0 (clean) to 100 (certain). The bands are the
same ones W1 Ch2 introduced for IP reputation:

    score >= 75   block       403 (or a fake success, for trap hits)
    score >= 40   challenge   proof of work on checkout (Round 4); a block before that
    score >= 20   monitor     logged; a cheaper proof of work on checkout (Round 4)
    otherwise     allow

Trade-off to keep in mind while tuning: every point you add to a signal moves
some real users up a band too. The checkpoint and the drop scoreboard report
both sides; a change that catches one more bot and blocks two shoppers is a
regression.
"""

# --- The decision ladder ------------------------------------------------------

BANDS = {"monitor": 20, "challenge": 40, "block": 75}

# --- Rate limits (token buckets, defenses/rate_limit.py) ----------------------
# name: (capacity, refill tokens per second). Capacity is the burst you allow;
# refill is the sustained rate. A shared IP (CGNAT, offices, universities)
# spends ONE bucket for everyone behind it, so per-IP buckets must stay loose.

RATE_LIMITS = {
    "ip": (60, 2.0),            # every request from one source IP
    "prefix": (200, 8.0),       # every request from one /24 (IPv4) or /64 (IPv6)
    "checkout_ip": (12, 0.2),   # POST /checkout from one source IP
}

# --- IP reputation points (defenses/ip_reputation.py, W1 Ch2 weights) ---------

IP_POINTS = {
    "tor_exit": 40,
    "open_proxy": 40,
    "datacenter": 40,       # inside a published cloud range
    "hosting_asn": 25,      # the ASN is a hosting company
    "known_vpn": 40,        # commercial and corporate VPN egress ranges
    "privacy_relay": 0,     # iCloud Private Relay: paying customers, not bots
}

# W1 Ch2 lesson: Private Relay egresses from Akamai and Cloudflare datacenters.
# Without this, every Safari user with Private Relay looks like a cloud VM.
TRUST_PRIVACY_RELAYS = True

# --- Header points (defenses/headers.py) --------------------------------------
# The W1 Ch3 modules already score on this 0-100 scale (a lone library UA is
# 40). Multiply here instead of editing them.

HEADER_WEIGHT = 1.0

# --- Session points (defenses/session_guard.py, W1 Ch4) -----------------------

SESSION_POINTS = {
    "no_form_view": 40,     # POST /checkout from a session that never loaded /drop
    "no_js_cookie": 20,     # the page's JavaScript never ran (or ran elsewhere)
    "form_too_fast": 30,    # form submitted sooner than MIN_FORM_SECONDS after it was served
    "asn_changed": 30,      # Round 4: the session moved to a different network (ASN)
}
MIN_FORM_SECONDS = 1.0      # autofill + a fast human finish a one-field form in ~1.5 s

# --- Trap points (defenses/traps.py, W1 Ch7) ----------------------------------

TRAP_POINTS = {
    "honeypot_field": 100,  # filled a field no human can see
    "trap_link": 100,       # followed a link no human can see (and robots.txt forbids)
    "trap_path": 100,       # asked for /.env, /wp-login.php ...
    "flagged_session": 100, # this session hit a trap earlier
    "flagged_ip": 20,       # this IP hit a trap in the last TRAP_IP_TTL seconds
}
TRAP_IP_TTL = 600           # a shared IP must not stay "guilty" for long
HONEYPOT_FIELD = "website"  # rename it on Drop Day and watch the autofill shopper

# --- Proof of work (defenses/proof_of_work.py, W1 Ch6) -------------------------
# Leading zero bits required per band. Expected work doubles per bit. Measured
# on the reference laptop: the page's WebCrypto solver in headless Chromium 153
# does ~80k hashes/s, a plain Python loop ~400k/s (and native code far more).
#   10 bits ~1k hashes    ~0.01 s in the browser
#   14 bits ~16k hashes   ~0.2 s
#   17 bits ~131k hashes  ~1.6 s in the browser, ~0.3 s in Python
# Each extra bit doubles the wait for EVERY shopper in that band, phones first.

POW_BITS = {"allow": 10, "monitor": 14, "challenge": 17}
POW_TTL = 120               # seconds a challenge stays valid
