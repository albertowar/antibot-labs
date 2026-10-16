"""Crawler identity verification (GIVEN infrastructure, not a student exercise).

Answers one question for the crawl-governance, enforcement and paywall layers:
*is this request really from the operator its User-Agent claims?* Two ways to
say yes:

  1. **Signed request** — W4 Ch2's Web Bot Auth verifier, byte-identical here
     (`defenses/web_bot_auth.py` over `defenses/httpsig.py`): an RFC 9421
     Ed25519 signature that verifies against a key the operator publishes
     (`defenses/key_directory.py`, this chapter's offline fork). The strong
     path, and the one a pay-per-crawl ledger needs: you cannot bill an IP range.
  2. **Published egress range** (W4 Ch1). The source IP falls in the ranges the
     operator publishes. Weaker — ranges leak, get reused, and a declared UA
     from outside them is exactly the stealth pivot of Round 1 — but it is what
     most sites have today.

The predecessor of this module carried its own simplified RFC 9421 verifier and
asked to be swapped for Chapter 2's when it existed; this is that swap. The
call site keeps the same Identity answer.
"""

from __future__ import annotations

from collections import namedtuple

from . import crawler_registry as registry
from . import web_bot_auth

Identity = namedtuple("Identity", "operator purpose verified how reason")


def verify(ctx) -> Identity:
    """Identity verdict for one request. Never raises.

    Precedence: a valid signature names the operator even if the UA is odd; a
    declared UA is then checked against published ranges; anything else is
    unverified. A declared UA with a *bad* signature is unverified, not merely
    unsigned: lying about identity is a stronger tell than saying nothing.
    """
    res = web_bot_auth.verify(ctx)
    if res.status == "verified":
        name, rec = registry.operator_for_agent(res.agent)
        if rec:
            return Identity(name, rec["purpose"], True, "signature",
                            f"signed by {name} ({(res.keyid or '')[:12]})")
        return Identity("", "", False, "unknown-signer",
                        f"valid signature from {res.agent}, which is not a registered crawler")
    ua = ctx.ua.raw
    d_name, d_rec = registry.operator_for_ua(ua)
    if not d_name:
        return Identity("", "", False, "none", "undeclared client")
    if res.status == "invalid":
        return Identity(d_name, d_rec["purpose"], False, "bad-signature",
                        "; ".join(res.reasons)[:160])
    if registry.ip_in_published_ranges(ctx.ip, d_rec):
        return Identity(d_name, d_rec["purpose"], True, "ip-range",
                        f"{ctx.ip} in {d_name}'s published ranges")
    return Identity(d_name, d_rec["purpose"], False, "declared-only",
                    f"claims {d_name} but {ctx.ip} is outside its ranges and unsigned")
