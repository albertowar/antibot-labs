"""
raffle_basics (Round 1): turn a speed contest into a lottery, and keep it one ticket per account.

First come, first served rewards whoever is fastest and most parallel; Round 0 showed sixty patient accounts take
every pair. A raffle moves the decision from milliseconds to the end of an entry window, so speed and connection
count stop mattering. What is left to game is the number of tickets. The store (demo_site/ext/raffle.py) records
entries and runs the draw; the POLICY is yours.

Rules to add, cheapest first:

  action:raffle_enter   1. a guest cannot enter           (block, 100)  ctx.attrs["entry"]["account"] is False
                        2. one entry per account          (block, 100)  ctx.attrs["entry"]["prior"] >= 1
  raffle:draw           3. every remaining entry is one ticket: weight 1.0

The facts in ctx.attrs["entry"] at entry time: account, prior (entries this account already holds), verified,
age_days, paid_orders, ship, card. At the draw, ctx.attrs["entries"] is the whole list as dicts: a check sets
`weight` (default 1.0) or `excluded` (a reason string) on an entry and the draw does the rest.

Think about it as you write it: this makes tickets equal. Does it make PEOPLE equal? Run Round 1 and read the
share of the units the 300-account crew gets next to its share of the tickets.

Reference: solutions/round1/defenses/raffle_basics.py (or `checkpoint.py --round 1 --catch-up`)
"""

from .pipeline import Check, Signal


def _enter(ctx):
    e = ctx.attrs.get("entry")
    if not e:
        return None
    # TODO (Round 1): return [Signal("raffle", "guest_entry", 100, "...")] for a guest, and
    #   [Signal("raffle", "second_entry", 100, "...")] when e["prior"] >= 1.
    return None


def _draw(ctx):
    entries = ctx.attrs.get("entries") or []
    # TODO (Round 1): give every entry one ticket (v["weight"] = 1.0) and ctx.note(raffle_tickets=len(entries)).
    return None


def _check(ctx):
    return _draw(ctx) if ctx.phase == "raffle:draw" else _enter(ctx)


CHECK = Check("raffle_basics", _check, phases=("action:raffle_enter", "raffle:draw"))
