"""Round 1 defense (YOUR CODE) — breached-credential gate at login.

The generic layers (per-IP rate limit, datacenter blocking) are already wired in
the store. A distributed stuffer that rotates egress walks straight past them: see
attacks/round1_stuffer.py. This module adds the signature a stuffer cannot hide.

The credential-stuffing economy runs on *breached* passwords. A combo list is a
breach dump. So: a login whose password is correct but appears in the breach corpus
must not hand out a bare session. Return CHALLENGE (a forced reset / step-up)
instead of ALLOW. Use the k-anonymity checker already in ctx: ctx["breach"].

ctx keys you get:
    valid_creds : bool  -- did email+password match a real account?
    password    : str   -- the password the client submitted
    breach      : BreachCorpus -- .is_breached(password) -> bool (k-anonymity)

Run `python tools/checkpoint.py --round 1 --catch-up` to drop in the reference
solution if you get stuck.
"""

from __future__ import annotations

from store import allow, Decision, INVALID


def evaluate(ctx) -> Decision:
    if not ctx["valid_creds"]:
        return Decision(INVALID, 0.0, "bad credentials")

    # TODO (Round 1): if the (correct) password is in the breach corpus, return a
    # CHALLENGE (forced reset) instead of allowing the session. Until you do, every
    # stuffing hit becomes a full account takeover.
    #   if ctx["breach"].is_breached(ctx["password"]):
    #       return challenge("breached password -> forced reset", score=100.0)

    return allow("login ok (no breach check wired yet)")
