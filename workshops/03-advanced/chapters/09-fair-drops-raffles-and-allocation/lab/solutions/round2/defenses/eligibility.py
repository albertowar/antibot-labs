"""
eligibility (Round 2, reference): who may enter, and what an entry weighs.

Round 1 left the numbers contest open: 300 fresh accounts are 300 tickets. A fresh account costs a reseller
almost nothing; an account with a history costs more. So make history count, in two places:

  action:raffle_enter   a verified email is required (block). The check runs at ENTRY, not at the draw, because
                        the fix is something the person can do right now (follow the link in the mail). A rule
                        that excludes someone silently, after the window closed, cannot be fixed by them.
  raffle:draw           the ticket's weight follows the account's trust:
                          1.0   the account is at least MIN_AGE_DAYS old, or has a paid order
                          0.25  a new account with no order (NEW_ACCOUNT_WEIGHT)

The draw then picks by weight, so a new account is a quarter of a ticket. It is a nudge, not a wall: nobody
is excluded for being new.

What it catches: the fresh farm. Three hundred new accounts weigh 75 tickets, not 300.
What it misses, and Round 2 shows it: a crew that BUYS accounts. An aged account with one old order is full
weight, and marketplaces sell them. Trust that can be bought is only a price.

Who it hurts. The genuinely new fan: a person who created an account last week to enter this drop now has a
quarter of everyone else's odds, and so does every honest newcomer to the store. That is the price of the rule,
and the report quotes it (new_real_fan). An unverified email is told to verify and can enter once they have.

Reference for the lesson; the stub is defenses/eligibility.py (or `checkpoint.py --round 2 --catch-up`).
"""

from .pipeline import Check, Signal

MIN_AGE_DAYS = 30
NEW_ACCOUNT_WEIGHT = 0.25


def _enter(ctx):
    e = ctx.attrs.get("entry")
    if e and e["account"] and not e["verified"]:
        return [Signal("eligibility", "unverified_email", 100, "verify your email to enter")]
    return None


def trust_weight(v):
    if v["age_days"] >= MIN_AGE_DAYS or v["paid_orders"] > 0:
        return 1.0
    return NEW_ACCOUNT_WEIGHT


def _draw(ctx):
    entries = ctx.attrs.get("entries") or []
    light = 0
    for v in entries:
        if not v["verified"]:
            v["excluded"] = "unverified_email"
            continue
        v["weight"] = trust_weight(v)
        light += v["weight"] < 1.0
    ctx.note(trust_weighted=light, trust_floor_days=MIN_AGE_DAYS)
    return None


def _check(ctx):
    return _draw(ctx) if ctx.phase == "raffle:draw" else _enter(ctx)


CHECK = Check("eligibility", _check, phases=("action:raffle_enter", "raffle:draw"))
