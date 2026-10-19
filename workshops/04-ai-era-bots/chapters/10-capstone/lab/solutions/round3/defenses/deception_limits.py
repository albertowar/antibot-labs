"""
W4 Ch10 Capstone — L3 deception within limits (REFERENCE SOLUTION, Round 3)

Traps go only to traffic the store would otherwise refuse. The store computes
``would_block`` from the same signals that drive enforcement, so the limit is
not a second opinion: it is the policy's own verdict, applied to what the page
contains instead of whether the page is served. Everyone the reservation
protects, the verified search crawler, the readers, the prefetching browsers
and the screen-reader cohort, gets a page with nothing hidden in it.

Why not also serve decoys to "suspicious" residential clients? Because that
is where CGNAT, campus networks and the shopper's own agent live, and because
a decoy served to a person is a lie told to a customer. The cost of the
limit: an extractor that rents residential egress and sends telemetry is not
poisoned here. It is caught by what it does next (honeypot fetches, volume,
W2 Ch4 clustering), not by what it read.
"""

from . import extractor_traps

EMPTY = {"hidden_records": [], "canary_note": None, "decoy_paragraphs": []}


def decorate(ctx):
    if not ctx.get("would_block"):
        return dict(EMPTY)
    if ctx.get("a11y"):
        return dict(EMPTY)   # belt and braces: never to a session that reads with the accessibility API
    ident = ctx.get("identity")
    if ident is not None and ident.operator and ident.verified:
        return dict(EMPTY)   # a crawler we could name and that followed the rules is never deceived
    return extractor_traps.decorate(ctx)
