"""
Capstone feature module: what the drop needs that no single chapter's ext gives it. No starter file is
edited, and nothing here decides anything (the decisions live in defenses/*.py).

    enricher            stamps the session when a drop page is served (defenses/flow.py reads it: the
                        server's own clock, not the collector's)
    challenge "proof"   the challenge the middle of the score scale serves: a small hashcash a browser
                        solves in well under a second (policy.PROOF_BITS). Chapters 1 to 3 enforce the
                        challenge band as a block because their stores register no type; the capstone
                        registers one so that "challenged" and "blocked" are different costs, which is
                        the trade-off Round 1's VDI customer is about.
    slots               an address field on the sign-up and drop forms (the account model counts how
                        many accounts ship to one address)
    after_request       remembers the address an account signed up with (defenses/session_model.py)

The login side of Round 4 lives in demo_site/ext/login9.py. Ext modules are not hot-reloaded: restart the
store after editing this file.
"""

import hashlib
import json
import secrets
import time

from flask import g, request

from defenses import flow, policy, session_model
from demo_site import hooks

PROOF_TTL_S = 120


def _leading_zero_bits(digest):
    bits = 0
    for byte in digest:
        if byte == 0:
            bits += 8
            continue
        return bits + 8 - byte.bit_length()
    return bits


def solve_proof(nonce, bits):
    """What proof.js does in the page (and what the simulated customers run)."""
    counter = 0
    while _leading_zero_bits(hashlib.sha256(f"{nonce}:{counter}".encode()).digest()) < bits:
        counter += 1
    return counter


# --- challenge "proof" -------------------------------------------------------------------------

def _issue(ctx):
    nonce = secrets.token_hex(8)
    ctx.redis.set(f"lab:proof:{nonce}", ctx.session.sid, ex=PROOF_TTL_S)
    return {"nonce": nonce, "bits": policy.PROOF_BITS}


def _verify(ctx, answer):
    nonce, counter = str((answer or {}).get("nonce", "")), (answer or {}).get("counter")
    if not isinstance(counter, int):
        return False, "no counter"
    owner = ctx.redis.getdel(f"lab:proof:{nonce}")          # single use, and only for the session it was issued to
    if owner is None or owner != ctx.session.sid:
        return False, "unknown, expired or foreign nonce"
    if _leading_zero_bits(hashlib.sha256(f"{nonce}:{counter}".encode()).digest()) < policy.PROOF_BITS:
        return False, "not enough leading zero bits"
    return True


# --- stamps and records ----------------------------------------------------------------------

def _stamp(ctx):
    """Runs at every level: record when a drop page was served."""
    if ctx.method == "GET" and ctx.path.startswith("/drop/"):
        ctx.session.set(flow.VIEW_KEY, int(time.time() * 1000))


def _remember_address(response):
    ctx = getattr(g, "ctx", None)
    if ctx is None or request.method != "POST" or request.path not in ("/register", "/api/register"):
        return response
    user_id = ctx.session.user_id
    body = request.get_json(silent=True) if request.is_json else request.form
    address = str((body or {}).get("address", ""))
    if user_id and address:
        session_model.record_address(ctx.redis, user_id, address)
    return response


def init(app):
    hooks.challenges.register("proof", issue=lambda ctx: _issue(ctx), verify=lambda ctx, answer: _verify(ctx, answer),
                              render="drop9/interstitial.html", clearance_ttl=policy.CLEARANCE_TTL)
    hooks.enricher(_stamp)
    hooks.slot("body_end", "drop9/proof_script.html")
    hooks.slot("form:register", "drop9/address.html")
    hooks.slot("form:drop", "drop9/address.html")
    app.after_request(_remember_address)
