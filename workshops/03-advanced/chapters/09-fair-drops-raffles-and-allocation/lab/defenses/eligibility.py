"""
eligibility (Round 2): who may enter, and what an entry weighs.

Round 1 left the numbers contest open: 300 fresh accounts are 300 tickets. A fresh account costs a reseller almost
nothing; an account with a history costs more. Make history count in two places:

  action:raffle_enter   a verified email is required (block, 100): ctx.attrs["entry"]["verified"]. Check it at ENTRY,
                        not at the draw: the person can fix it now (follow the link in the mail). A rule that
                        excludes someone silently after the window closed cannot be fixed by them.
  raffle:draw           the ticket's weight follows the account's trust:
                          1.0   age_days >= MIN_AGE_DAYS, or paid_orders > 0
                          NEW_ACCOUNT_WEIGHT (0.25)   a new account with no order
                        and an unverified entry is excluded: v["excluded"] = "unverified_email"

The draw picks by weight, so a new account is a fraction of a ticket. It is a nudge, not a wall: nobody is
excluded for being new. Run Round 2 and read what it does to the fresh farm, to the crew that BUYS aged accounts,
and to the honest newcomer (new_real_fan).

Reference: solutions/round2/defenses/eligibility.py (or `checkpoint.py --round 2 --catch-up`)
"""

from .pipeline import Check, Signal

MIN_AGE_DAYS = 30
NEW_ACCOUNT_WEIGHT = 0.25


def _enter(ctx):
    e = ctx.attrs.get("entry")
    # TODO (Round 2): [Signal("eligibility", "unverified_email", 100, "verify your email to enter")] for a signed-in
    #   account whose email is not verified.
    return None


def trust_weight(v):
    # TODO (Round 2): 1.0 for an account that is MIN_AGE_DAYS old or has a paid order, else NEW_ACCOUNT_WEIGHT.
    return 1.0


def _draw(ctx):
    entries = ctx.attrs.get("entries") or []
    # TODO (Round 2): for each entry: exclude an unverified one, else v["weight"] = trust_weight(v).
    #   ctx.note(trust_weighted=<how many got a weight below 1>, trust_floor_days=MIN_AGE_DAYS)
    return None


def _check(ctx):
    return _draw(ctx) if ctx.phase == "raffle:draw" else _enter(ctx)


CHECK = Check("eligibility", _check, phases=("action:raffle_enter", "raffle:draw"))
