"""
scalping_funnel (Round 2, reference): make the buy path behave like a human one, and cap units per device.

The economics. A scalper profits from scarce stock bought faster, and in greater quantity, than a
person can. Its traffic looks like buying because it IS buying, so we do not try to "block a bot":
we take the speed and the parallelism away and leave price and availability alone.

Three signals, each a scalper tell that costs a shopper nothing:
  1. no prior view of the drop in this session -> the buy skipped the funnel   (block)
  2. this device already tried to buy          -> one unit per device           (block)
  3. view-to-buy under a person's click time   -> machine-speed funnel          (challenge)

Order: the cheap, certain tests first. The cap counts attempts that passed test 1, in Redis, with a
window, so a patient bot that waits out the floor still gets one unit per device cookie.

Who it hurts. A decisive person on a fast connection can clear a 1-second floor; it sits below real
human speed and is a challenge, not a block. Shared and family devices collide on one `did`: bind the
cap to the account and the payment card too. `did` is attacker-chosen, so a bot with a fresh cookie
per attempt walks past the cap; a fingerprint (W2 Ch4) or account age has to carry that.
"""

from .pipeline import Check, Signal

MIN_FUNNEL_SECONDS = 1.0
PURCHASE_CAP = 1
WINDOW_S = 900


def _check(ctx):
    drop = ctx.attrs.get("drop")
    if not drop:
        return None
    if drop["view_age_s"] is None:
        return [Signal("funnel", "no_view", 100, "buy with no view of the drop this session")]
    key = f"lab:funnel:buy:{drop['sku']}:{drop['device']}"
    tries = ctx.redis.incr(key)
    ctx.redis.expire(key, WINDOW_S)
    if tries > PURCHASE_CAP:
        return [Signal("funnel", "device_cap", 100, f"device already tried {tries - 1}x")]
    if drop["view_age_s"] < MIN_FUNNEL_SECONDS:
        return [Signal("funnel", "machine_speed", 70, f"view to buy in {drop['view_age_s']:.2f}s < {MIN_FUNNEL_SECONDS}s")]
    return None


CHECK = Check("scalping_funnel", _check, phases=("action:drop_buy",))
