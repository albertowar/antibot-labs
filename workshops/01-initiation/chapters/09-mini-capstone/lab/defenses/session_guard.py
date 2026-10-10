"""
W1 Ch9 — Layer: session guard (W1 Ch5).

The store keeps a server-side session in Redis for every visitor (the
session itself exists from Round 0; this layer only READS it). Because the
state lives on the server, a bot can drop its cookie but cannot edit what
we remember about it.

Signals, on POST /checkout only (points in policy.SESSION_POINTS):
    no_form_view    the session never loaded /drop, so nobody saw the form
    no_js_cookie    the page's tiny script never ran: js_ok is missing or wrong
    form_too_fast   submitted < MIN_FORM_SECONDS after the form was served

Round 4 adds `check_binding`, on every request:
    asn_changed     the session was created on one network (ASN) and is now
                    used from another. Session minting does exactly this: a
                    browser on IP A creates the session, cheap workers on
                    IPs B, C, D... spend it.

What it catches: form fillers that never render the page (wave 2), and
handoffs across a rotating proxy pool (wave 3, Round 4).
What it misses: anything that drives a real browser on one IP (wave 4).
False positives:
    - no-JS shoppers (NoScript, some accessibility setups) always score
      no_js_cookie. That is 20 points, "monitor", on purpose.
    - power users with autofill submit in ~1.5 s. Raise MIN_FORM_SECONDS to
      3 and watch the autofill shopper on the scoreboard.
    - phones that move from home Wi-Fi to cellular change ASN mid-session.
      asn_changed is 30 points: friction (a harder proof of work), not a block.
"""

import json
import secrets
import time

import policy
from ladder import Signal

COOKIE = "sid"
TTL = 1800  # seconds


class Session:
    """A Redis hash behind an opaque random cookie. Never trust the client to hold state."""

    def __init__(self, redis, sid, data, new):
        self.redis, self.sid, self.data, self.new = redis, sid, data, new

    @classmethod
    def load_or_create(cls, redis, sid, network):
        if sid:
            data = redis.hgetall(f"sess:{sid}")
            if data:
                return cls(redis, sid, data, new=False)
        sid = secrets.token_urlsafe(24)
        data = {
            "created_at": f"{time.time():.3f}",
            "asn": str(network.get("asn")),
            "js_nonce": secrets.token_hex(8),
            "csrf": secrets.token_urlsafe(16),
            "purchases": "0",
            "flags": "[]",
        }
        redis.hset(f"sess:{sid}", mapping=data)
        redis.expire(f"sess:{sid}", TTL)
        return cls(redis, sid, data, new=True)

    def get(self, key, default=None):
        return self.data.get(key, default)

    def set(self, key, value):
        self.data[key] = str(value)
        self.redis.hset(f"sess:{self.sid}", key, str(value))
        self.redis.expire(f"sess:{self.sid}", TTL)

    def incr(self, key):
        value = self.redis.hincrby(f"sess:{self.sid}", key, 1)
        self.data[key] = str(value)
        return value

    def flags(self):
        return json.loads(self.data.get("flags", "[]"))

    def add_flag(self, flag):
        flags = self.flags()
        if flag not in flags:
            self.set("flags", json.dumps(flags + [flag]))

    def expected_js_cookie(self):
        """What the page script writes: the nonce, reversed (W1 Ch5)."""
        return self.get("js_nonce", "")[::-1]


def check(ctx):
    """Layer entry point (Round 3): only the protected action is judged."""
    if not (ctx.method == "POST" and ctx.path == "/checkout"):
        return []
    s, points, signals = ctx.session, policy.SESSION_POINTS, []

    served = s.get("form_served_at")
    if not served:
        signals.append(Signal("session", "no_form_view", points["no_form_view"],
                              "checkout from a session that never loaded /drop"))
    else:
        elapsed = time.time() - float(served)
        if elapsed < policy.MIN_FORM_SECONDS:
            signals.append(Signal("session", "form_too_fast", points["form_too_fast"],
                                  f"form submitted {elapsed:.2f}s after it was served"))

    if ctx.cookies.get("js_ok") != s.expected_js_cookie():
        signals.append(Signal("session", "no_js_cookie", points["no_js_cookie"],
                              "js_ok cookie missing or wrong: the page script never ran here"))
    return signals


def check_binding(ctx):
    """Layer entry point (Round 4): the session must stay on the network that created it."""
    born_on = ctx.session.get("asn")
    now_on = str(ctx.network.get("asn"))
    if ctx.session.new or born_on in (None, "None") or born_on == now_on:
        return []
    return [Signal("session", "asn_changed", policy.SESSION_POINTS["asn_changed"],
                   f"session created on AS{born_on}, now used from AS{now_on}")]
