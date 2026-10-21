"""
raffle_basics (Round 1, reference): turn a speed contest into a lottery, and keep it one ticket per account.

First come, first served rewards whoever is fastest and most parallel, and Round 0 showed what that is worth:
sixty patient accounts took every pair. A raffle moves the decision from milliseconds to the end of an entry
window. Speed and connection count stop mattering. What is left to game is the number of tickets.

The rules this check owns (the store's routes only record entries; the policy is yours):

  action:raffle_enter   1. a guest cannot enter                      (block): no account, nothing to hold to the rule
                        2. one entry per account                      (block): the second ticket is the cheapest cheat
  raffle:draw           3. every remaining entry is one ticket        (weight 1.0): the draw is uniform

The facts you get in ctx.attrs["entry"] at entry time: account (bool), prior (entries this account already
holds in this event), verified, age_days, paid_orders, ship, card. At the draw, ctx.attrs["entries"] is the
whole list as dicts; a check changes `weight` or sets `excluded` and the draw does the rest.

What it does NOT do, and Round 1 shows it: one ticket per ACCOUNT is not one ticket per PERSON. A reseller
with 300 fresh accounts holds 300 tickets, and wins in proportion: its share of the units is about its share
of the tickets. The raffle took away the speed advantage; it did not take away the numbers advantage.

Who it hurts. Nobody who was going to enter once. A fan with two accounts (one old, one new) loses nothing by
the rule. A guest-checkout fan is told to sign in (the page says so).

Reference for the lesson; the stub is defenses/raffle_basics.py (or `checkpoint.py --round 1 --catch-up`).
"""

from .pipeline import Check, Signal


def _enter(ctx):
    e = ctx.attrs.get("entry")
    if not e:
        return None
    if not e["account"]:
        return [Signal("raffle", "guest_entry", 100, "an entry needs a signed-in account")]
    if e["prior"] >= 1:
        return [Signal("raffle", "second_entry", 100, f"this account already holds {e['prior']} ticket(s)")]
    return None


def _draw(ctx):
    entries = ctx.attrs.get("entries") or []
    for v in entries:
        v["weight"] = 1.0
    ctx.note(raffle_tickets=len(entries), raffle_weighting="uniform")
    return None


def _check(ctx):
    return _draw(ctx) if ctx.phase == "raffle:draw" else _enter(ctx)


CHECK = Check("raffle_basics", _check, phases=("action:raffle_enter", "raffle:draw"))
