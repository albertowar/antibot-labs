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

# The capstone keeps the series scale it inherited from W2 Ch8 / W4 Ch4:
# < 30 allow, 30-59 challenge, >= 60 block (monitor is just logging colour here).
BANDS = {"monitor": 15, "challenge": 30, "block": 60}

# The challenge type to serve when a check asks for a challenge without naming one.
# None in the W1 starter: the challenge band is enforced as a block until a chapter
# registers a type (W1 Ch5 captcha, W1 Ch6 proof of work, W2 Ch4 JS challenge).
DEFAULT_CHALLENGE = "pow"   # the agent policy may pick captcha_image or confirm_code per client

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


# Web Bot Auth (RFC 9421; defenses/web_bot_auth.py is byte-identical to W4 Ch2's and reads
# these two names here). TRUSTED_AGENTS maps a Signature-Agent ORIGIN to what it is; the
# seed entries are the operators the store launches with, and Round 4's onboarding
# (tools/approve.py onboard-operator) extends it at runtime through
# rules/trusted_operators.json, which POST /lab/reset restores to the seed.
SIGNATURE_MAX_WINDOW_S = 300

_TRUST_SEED = {
    "https://agents.lab-provider.test": {"category": "shopping-agent vendor"},
    "https://trainbot.example": {"category": "licensed training crawler"},
    "https://labsearch.example": {"category": "search crawler"},
}


class _LiveTrust(dict):
    """The seed plus whatever a person onboarded (re-read per lookup: the file is tiny,
    the verifier asks once per signed request, and onboarding must take effect live)."""

    FILE = __import__("os").path.join(__import__("os").path.dirname(__file__), "..",
                                      "rules", "trusted_operators.json")

    def _extra(self):
        import json
        import os
        if not os.path.exists(self.FILE):
            return {}
        try:
            with open(self.FILE) as fh:
                return {k: dict(v) for k, v in json.load(fh).get("trusted", {}).items()}
        except (ValueError, OSError):
            return {}

    def get(self, key, default=None):
        return dict.get(self, key) or self._extra().get(key, default)

    def __contains__(self, key):
        return dict.__contains__(self, key) or key in self._extra()


TRUSTED_AGENTS = _LiveTrust(_TRUST_SEED)
