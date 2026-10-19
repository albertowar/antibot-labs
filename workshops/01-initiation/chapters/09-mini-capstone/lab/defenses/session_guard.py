"""
W1 Ch8 — Rounds 3 & 4: read the session as evidence.

Once the session is trustworthy (server-side, consumed once, rate-limited at birth),
it is a record of how this visitor behaved. No single fact is proof, so each is a
weighted signal and policy.decide() adds them up (monitor 20, challenge 40, block 75).

CHECK (Round 3), on the redeem action:
    no_landing          the session never loaded "/", so nobody saw the store
    no_js_cookie        the page's one-line script never ran: js_ok is missing or wrong
    session_too_young   the session is younger than a human visit (MIN_SESSION_SECONDS)

BINDING_CHECK (Round 4), on the redeem action:
    ua_changed          the User-Agent / Client-Hints hash differs from session creation.
                        Browsers do not change identity mid-visit; a handed-off session does.
    asn_changed         the session was created on one network and is used from another.

What CHECK catches: a script that goes straight for the voucher without rendering the page.
What it misses: a script that re-implements the one-line JS and waits (the red step does this).
What BINDING_CHECK catches: session minting — a browser mints a clean session, then a cheap
    HTTP client spends it. The client forgets the Client Hints; the hash moves.
What it misses: minting that copies every identity header (the red step), and a real browser
    driven end to end.

False positives (why the weights are what they are):
    - no-JS shoppers (NoScript, some accessibility setups) always miss js_ok. That is why the
      shipped weight (40) is wrong: it blocks them. The README's Round 3 fails on purpose, then
      drops it to 25 ("monitor"), so a no-JS human is logged, not blocked.
    - a phone that moves from Wi-Fi to cellular changes ASN mid-session. `asn_changed` is 20
      (monitor), not a block, for exactly this reason. An exact-IP change is not a signal at all.
"""

import hashlib

from . import policy
from .pipeline import Check, Signal


def _ua_hash(ctx):
    ua = ctx.header("User-Agent", "") or ""
    ch = ctx.header("Sec-CH-UA", "") or ""
    return hashlib.sha256(f"{ua}|{ch}".encode()).hexdigest()[:16]


def _signals(ctx):
    s, pts, out = ctx.session, policy.SESSION_POINTS, []
    if not s.get("landing"):
        out.append(Signal("session", "no_landing", pts["no_landing"],
                          "redeem from a session that never loaded the store's home page"))
    if ctx.cookies.get("js_ok") != (s.get("js_nonce", "") or "")[::-1]:
        out.append(Signal("session", "no_js_cookie", pts["no_js_cookie"],
                          "js_ok cookie missing or wrong: the page script never ran here"))
    if s.age_seconds < policy.MIN_SESSION_SECONDS:
        out.append(Signal("session", "session_too_young", pts["session_too_young"],
                          f"session is {s.age_seconds:.1f}s old"))
    return out


def _binding(ctx):
    s, pts, out = ctx.session, policy.SESSION_POINTS, []
    born_ua = s.get("ua_hash")
    if born_ua and born_ua != _ua_hash(ctx):
        out.append(Signal("session", "ua_changed", pts["ua_changed"],
                          "User-Agent / Client-Hints changed since this session was created"))
    born_asn = s.get("created_asn")
    now_asn = str(ctx.edge.asn)
    if not s.new and born_asn not in (None, "", "0", "None") and born_asn != now_asn:
        out.append(Signal("session", "asn_changed", pts["asn_changed"],
                          f"session created on AS{born_asn}, now used from AS{now_asn}"))
    return out


CHECK = Check("session_guard", _signals, phases=("action:promo_redeem",))
BINDING_CHECK = Check("session_binding", _binding, phases=("action:promo_redeem",))
