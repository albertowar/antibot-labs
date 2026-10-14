"""
scalping_funnel (Round 2): make the buy path behave like a human one, and cap units per device.

The economics. A scalper profits from scarce stock bought faster, and in greater quantity, than a
person can. Its traffic looks like buying because it IS buying, so "is this a bot?" is the wrong
question and blocking hard hurts customers on launch day. Take the speed and the parallelism away
instead, without touching price or availability.

The facts you get. demo_site/ext/economies.py fills ctx.attrs["drop"] on a drop purchase
(POST /drop/<sku> and POST /api/buy):

    sku         str          the drop
    view_age_s  float|None   seconds since this session first viewed the drop, None if it never did
    device      str          the `did` device cookie (the session id when there is none)

and the check runs at `action:drop_buy`, just before the stock is decremented.

Signals to add, cheapest first (the starter's bands: 40 challenge, 75 block):

  1. never viewed the drop      -> the buy skipped the funnel     (block, 100)
  2. device already tried once  -> one unit per device            (block, 100)
  3. view_age_s under the floor -> faster than a person can click (challenge, 70)

There is no challenge solver in this lab, so a challenge is enforced as a block (and the scoreboard
shows it that way). Count attempts in Redis with ctx.redis.incr(...) and let the key expire.

Who it hurts. A decisive person on a fast connection can clear a 1-second floor; that is why it is a
challenge and sits below real human speed. Family devices and shared kiosks collide on one `did`; bind
the cap to the account and the payment card as well before you ship. The `did` cookie is attacker-chosen:
a scalper with a fresh cookie per attempt walks past the cap, which is where a fingerprint (W2 Ch4) or an
account-age rule has to take over.

Reference: solutions/round2/defenses/scalping_funnel.py (or `checkpoint.py --round 2 --catch-up`)
"""

from .pipeline import Check, Signal

MIN_FUNNEL_SECONDS = 1.0      # view -> buy faster than this is machine speed
PURCHASE_CAP = 1              # buy attempts per device for a drop
WINDOW_S = 900


def _check(ctx):
    drop = ctx.attrs.get("drop")
    if not drop:
        return None
    # TODO (Round 2): return a list with ONE Signal for the first rule that fires, else None.
    #   Signal("funnel", "no_view", 100, "...")  /  Signal("funnel", "device_cap", 100, "...")
    #   Signal("funnel", "machine_speed", 70, "...")
    return None


CHECK = Check("scalping_funnel", _check, phases=("action:drop_buy",))
