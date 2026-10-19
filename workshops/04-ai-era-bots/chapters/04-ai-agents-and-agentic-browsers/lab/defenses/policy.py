"""
Policy: every number the defender tunes, and how a verdict becomes an HTTP answer.

pipeline.py decides WHICH checks run; this file decides HOW MUCH each signal
counts and WHERE the lines are. Chapters tune these values; W2 Ch8 replaces
decide() with calibrated weights; in production an ops team hot-reloads them from a config file.

One scale for every check: 0 (clean) to 100 (certain).

    score >= 60   block       403 (W4 Ch4 scale; the W1 starter blocks at 75)
    score >= 30   challenge   serve a registered challenge type, else a 403 (starter: 40)
    score >= 15   monitor     logged, served (starter: 20)
    otherwise     allow

Every point you add to a signal moves some real users up a band too. The
scoreboard reports both sides; a change that catches one more bot and blocks
two shoppers is a regression.
"""

# W4 Ch4: the agent chapter's scale is the one W2 Ch8/Ch9 use, so nothing has to be relearned:
# under 30 allow, 30-59 challenge (hand the decision back to a person), 60 and over block.
BANDS = {"monitor": 15, "challenge": 30, "block": 60}

# The challenge type to serve when a check asks for a challenge without naming one.
# None in the W1 starter: the challenge band is enforced as a block until a chapter
# registers a type (W1 Ch5 captcha, W1 Ch6 proof of work, W2 Ch4 JS challenge).
# W4 Ch4 registers "step_up" (demo_site/ext/agents.py): a one-time code "emailed" to the account.
DEFAULT_CHALLENGE = "step_up"

# Seconds a cleared challenge stays valid for the session.
CLEARANCE_TTL = 15 * 60

# Token buckets: name -> (capacity, refill per second). Capacity is the burst you
# allow; refill is the sustained rate. Used by Ctx.bucket(name, key).
RATE_LIMITS = {
    "ip": (60, 2.0),
    "prefix": (200, 8.0),
    "login_ip": (10, 0.1),
    "checkout_ip": (12, 0.2),
    # W4 Ch4 L0 (defenses/request_checks.py): deliberately loose. Office NAT and CGNAT put hundreds of
    # people behind one address, and a user-directed agent makes one purchase from one home address.
    "agent_ip": (240, 8.0),
}

# W4 Ch4: the Web Bot Auth trust policy (defenses/web_bot_auth.py reads these two names, so that file
# stays byte-identical to W4 Ch2's). Discovery is not trust: the second operator below publishes a
# perfectly valid key directory and is deliberately not listed. "category" is what the operator is.
TRUSTED_AGENTS = {
    "https://agents.lab-provider.test": {"category": "user-agent"},
}
SIGNATURE_MAX_WINDOW_S = 300

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
