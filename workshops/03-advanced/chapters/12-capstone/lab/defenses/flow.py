"""
flow (Round 2): how the session got to the buy, measured by the SERVER's clock.

Chapter 5's behavior layers read what the page's collector reports, and a collector report is a claim the
client makes. These two rules read only what the server saw itself, so they cannot be replayed or edited:

    bought < MIN_DWELL_MS after the drop page was served       DWELL_POINTS   (a script clicks Buy the moment it loads)
    bought with no view of the drop page in this session       COLD_BUY_POINTS (a direct API call; Chapter 5's
                                                                 "no telemetry" rule fires too, this one needs no JS)

The page-served time is stamped by demo_site/ext/drop9.py on every GET of a drop page.

Where it fails:
  - A power user who knows the URL and buys in 1.5 s sits right above the line. Raise MIN_DWELL_MS and
    you start challenging the customers who prepared for the drop.
  - A bot that waits is not caught here at all (Round 3's farm sleeps like a person).
"""

import time

from . import policy
from .pipeline import Check, Signal

VIEW_KEY = "drop_view_ms"          # session field: when the drop page was last served (ms)


def _check(ctx):
    viewed = ctx.session.get(VIEW_KEY)
    if not viewed:
        return [Signal("flow", "cold_buy", policy.COLD_BUY_POINTS, "buy without a view of the drop page in this session")]
    dwell = int(time.time() * 1000) - int(viewed)
    ctx.note(dwell_ms=dwell)
    if dwell < policy.MIN_DWELL_MS:
        return [Signal("flow", "short_dwell", policy.DWELL_POINTS,
                       f"bought {dwell} ms after the page was served (min {policy.MIN_DWELL_MS})")]
    return None


CHECK = Check("flow", _check, phases=("action:drop_buy",))
