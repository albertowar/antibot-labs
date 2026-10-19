"""
W4 Ch4/Ch10 — verified agent identity, on the canonical Ch2 verifier (GIVEN)

`defenses/web_bot_auth.py` (byte-identical to W4 Ch2's) answers the two
questions in order: did a key the Signature-Agent origin publishes sign THIS
message (`verify`), and is that origin one this store trusts, with a message
safe to act on — window capped, nonce unseen (`trust`, reading
policy.TRUSTED_AGENTS and policy.SIGNATURE_MAX_WINDOW_S)? This module folds the
two answers into the status vocabulary the capstone's governance layer speaks:

    none              no usable Web Bot Auth signature
    verified          signed by a trusted operator, fresh, nonce new
    unknown_operator  a VALID signature from an origin we do not trust: identity
                      noted, no entitlement (discovery is not trust)
    invalid           a signature was presented and FAILED: forgery, tamper,
                      unpublished key — nobody does that by accident (+60)
    expired           the window is longer than policy allows, or stale: a
                      replayable credential (+60)
    replayed          the nonce was already seen (+60)

What a verified identity proves: that the request came from infrastructure
holding the operator's key. What it does NOT prove: who the human behind the
agent is, what they asked for, or whether they consented to this purchase.
That is what mandates are for.
"""

from . import web_bot_auth


def _result(status, operator=None, keyid=None, reasons=()):
    return {"status": status, "operator": operator, "keyid": keyid, "reasons": list(reasons)}


def verify(ctx):
    res = web_bot_auth.verify(ctx)
    if res.status == "unverified":
        return _result("none", reasons=res.reasons)
    operator = (res.agent or "").removeprefix("https://")
    if res.status == "invalid":
        return _result("invalid", operator, res.keyid, res.reasons)
    tr = web_bot_auth.trust(res, ctx)
    if tr.entitled:
        return _result("verified", operator, res.keyid, tr.reasons)
    if tr.block:
        why = " ".join(tr.reasons)
        status = "replayed" if "replay" in why else "expired"
        return _result(status, operator, res.keyid, tr.reasons)
    return _result("unknown_operator", operator, res.keyid, tr.reasons)


def score(identity):
    if identity["status"] in ("none", "verified", "unknown_operator"):
        return 0, []
    return 60, [f"Claimed agent identity did not verify ({identity['status']}): "
                + "; ".join(identity["reasons"])]
