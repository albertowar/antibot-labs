"""Crawler identity (GIVEN infrastructure, not a student exercise).

Answers one question for the policy, enforcement, maze and paywall layers: *is this request really
from the operator it claims?* Two ways to say yes, strongest first:

  1. **A signed request** (W4 Ch2's Web Bot Auth). `Signature-Agent`, `Signature-Input` and
     `Signature` carry an RFC 9421 HTTP Message Signature; the verifier fetches the origin's key
     directory, checks the Ed25519 signature, and `trust()` applies the policy (a trusted origin,
     a short window, a nonce never seen before). This is the canonical verifier, copied byte for
     byte from W4 Ch2 (`web_bot_auth.py`, `httpsig.py`, `key_directory.py`; see `shared.json`),
     and it is the only path that can carry a *bill*: you cannot invoice an IP range.
  2. **A published egress range** (W4 Ch1). The source address falls in the ranges the operator
     publishes (`crawler_registry.py`). Weaker (ranges leak, get reused, and a declared UA from
     outside them is exactly the Round 2 stealth pivot) but it is what most sites have today.

A declared User-Agent that proves nothing is *declared but unverified*; a declared UA with a
signature that fails is worse (lying about identity is a stronger tell than saying nothing), and
`how` says which. One verdict per request: the result is cached in `ctx.attrs["identity"]`, because
`trust()` spends the signature's nonce and a second call would call a genuine request a replay.

Wired at LADDER[1] so the identity rides in the decision log (`extra.crawler`); every later layer
calls `identify(ctx)` and gets the cached answer.
"""

from __future__ import annotations

from collections import namedtuple

from . import crawler_registry as registry
from . import web_bot_auth
from .pipeline import Check, Signal

Identity = namedtuple("Identity", "operator purpose verified how reason")

NONE = Identity("", "", False, "none", "undeclared client")


def identify(ctx) -> Identity:
    """Identity verdict for this request (cached). Never raises."""
    cached = ctx.attrs.get("identity")
    if cached is not None:
        return cached
    ctx.attrs["identity"] = ident = _identify(ctx)
    return ident


def _identify(ctx) -> Identity:
    ua_name, ua_rec = registry.operator_for_ua(ctx.ua.raw)
    signed = bool(ctx.header("Signature-Input") and ctx.header("Signature"))
    why = ""
    if signed:
        res = web_bot_auth.verify(ctx)
        why = "; ".join(res.reasons)
        if res.status == "verified":
            trust = web_bot_auth.trust(res, ctx)
            why = "; ".join(trust.reasons)
            name, rec = registry.operator_for_agent(res.agent)
            if trust.entitled and name:
                return Identity(name, rec["purpose"], True, "signature", f"signed by {name} ({res.keyid[:8]}...)")
            how = "replay" if trust.block else "untrusted-signature"
        else:
            how = "bad-signature"
        if ua_name:
            return Identity(ua_name, ua_rec["purpose"], False, how, why or how)
        return Identity("", "", False, how, why or how)
    if not ua_name:
        return NONE
    if registry.ip_in_published_ranges(ctx.ip, ua_rec):
        return Identity(ua_name, ua_rec["purpose"], True, "ip-range", f"{ctx.ip} is in {ua_name}'s published ranges")
    return Identity(ua_name, ua_rec["purpose"], False, "declared-only",
                    f"claims {ua_name} but {ctx.ip} is outside its ranges and unsigned")


def _check(ctx):
    ident = identify(ctx)
    if ident.operator or ident.how != "none":
        ctx.note(crawler=ident.operator or None, crawler_verified=ident.verified, crawler_how=ident.how,
                 crawler_reason=ident.reason[:160])
    return [Signal("bot_identity", ident.how, 0, ident.reason[:120])]


CHECK = Check("bot_identity", _check)
