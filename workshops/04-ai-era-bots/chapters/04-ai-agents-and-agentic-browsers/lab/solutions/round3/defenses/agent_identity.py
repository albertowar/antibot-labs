"""
W4 Ch4, L3 verified agent identity (Round 3)

The shared Web Bot Auth verifier (defenses/web_bot_auth.py, defenses/httpsig.py,
defenses/key_directory.py: W4 Ch2's, byte for byte) answers two separate questions:

    verify(ctx)       did the holder of a key that the Signature-Agent origin publishes sign THIS
                      message?  -> verified | invalid | unverified
    trust(res, ctx)   should we act on it?  Only origins in policy.TRUSTED_AGENTS are entitled; a
                      window longer than policy.SIGNATURE_MAX_WINDOW_S is a replayable credential;
                      a nonce is spent once.  -> entitled | not entitled | block

This module is what the STORE does with those two answers: one identity record per request, which
Round 3's other checks and the principal (defenses/principal.py) read. Statuses:

    none          no Web Bot Auth headers at all
    verified      a valid signature by a key a TRUSTED origin publishes, fresh, nonce unused
    untrusted     a valid signature by an origin we have never heard of (the attacker's own, perfectly
                  signed, directory): discovery is not trust
    replayed      valid, but the window is longer than policy allows, or the nonce was already spent
    invalid       the signature does not hold: forged, tampered, expired, a key the origin never published
    unverified    headers present but unusable: a bare Signature-Agent claim, or the directory could
                  not be fetched

A claim that is present and does not reach `verified` scores like a hostile request (+60): nobody
presents a bad signature by accident. `none` and `verified` score 0.

The trade-off to decide, not to hide: `unverified` includes "the operator's key directory was
down". Scoring it +60 blocks honest agents during an operator outage (fail closed); scoring it 0 lets a
bare claim through (fail open). The lab fails closed; production usually serves a lane below the
verified one.

What a verified identity proves: that the request came from infrastructure holding the operator's
key. What it does NOT prove: who the human behind the agent is, what they asked for, or whether they
consented to this purchase. Round 4 deals with that.
"""

from . import key_directory, web_bot_auth
from .pipeline import Check, Signal

HEADERS = ("Signature-Agent", "Signature-Input", "Signature")


def _result(status, operator=None, keyid=None, reason=""):
    return {"status": status, "operator": operator, "keyid": keyid, "reasons": [reason] if reason else []}


def _host(origin):
    return key_directory.origin_authority(origin or "")[0] if origin else None


def verify(ctx):
    """The identity record for this request: {"status", "operator", "keyid", "reasons"}."""
    if not any(ctx.header(h) for h in HEADERS):
        return _result("none")
    res = web_bot_auth.verify(ctx)
    host, why = _host(res.agent), "; ".join(res.reasons)
    if res.status == "invalid":
        return _result("invalid", host, res.keyid, why)
    if res.status != "verified":
        return _result("unverified", host, res.keyid, why)
    trust = web_bot_auth.trust(res, ctx)
    if trust.entitled:
        return _result("verified", host, res.keyid, "; ".join(trust.reasons))
    return _result("replayed" if trust.block else "untrusted", host, res.keyid, "; ".join(trust.reasons))


def score(identity):
    if identity["status"] in ("none", "verified"):
        return 0, []
    return 60, [f"Claimed agent identity did not verify ({identity['status']}): " + "; ".join(identity["reasons"])]


def _check(ctx):
    from . import principal as who      # principal.py imports this module: import it late
    ident = who.identity(ctx)
    points, reasons = score(ident)
    return [Signal("agent_identity", ident["status"], points, "; ".join(reasons)[:140])] if points else None


CHECK = Check("agent_identity", _check, phases=("action:drop_buy",))
