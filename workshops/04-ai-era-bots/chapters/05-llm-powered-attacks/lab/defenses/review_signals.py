"""
Round 1 defense (YOUR CODE): content-independent review signals.

The LLM review farm writes 40 unique, on-topic reviews, so content_heuristics.py passes every one of them.
What the farm cannot fake cheaply is *who* is writing: the accounts were registered this morning, none of
them bought the product, and forty of them share a handful of devices and egress IPs. Those are the signals.

`facts(ctx)` is written for you. It returns, for the review being posted (this one counted):

    account_age_days        float   how old the reviewing account is (a guest counts as 0)
    verified_purchase       bool    did this account buy this SKU?
    reviews_by_device_24h   int     reviews from this device cookie (`did`) in the last day
    reviews_by_ip_1h        int     reviews from this egress IP in the last hour

Two ways to answer, because the gate's verdict set is closed (allow, monitor, challenge, block, ...):

  * **block**: `return Verdict("block", signals=(Signal("review_signals", "name", 90, "why"),))` refuses the
    review with a 403. A real reviewer who is blocked is a false positive.
  * **hold**: set `ctx.attrs["review_hold"] = "why"` (and return a small Signal so it shows in the log).
    The review is accepted but parked as `pending`: it is not published, so it does not count as attacker
    success, and a moderator can still approve it. `demo_site/ext/llm_surfaces.py` does the parking in a
    `hooks.on_action("review", ...)` handler and answers 202. A hold is friction, not failure.

`python tools/checkpoint.py --round 1 --catch-up` drops in the reference solution.
"""

from .pipeline import Check, Signal, Verdict  # noqa: F401  (Signal and Verdict are what you will return)

NEW_ACCOUNT_DAYS = 7
DEVICE_CAP_24H = 2
IP_CAP_1H = 8        # generous on purpose: carrier-grade NAT puts a whole street behind one address


def facts(ctx):
    """Plumbing, not the exercise. Counts this review in the device and IP windows."""
    from demo_site.models import Order, OrderItem, utcnow
    body = ctx.json if isinstance(ctx.json, dict) else ctx.form
    sku = str(body.get("sku") or ctx.path.rsplit("/", 1)[-1])
    user = ctx.user
    age = (utcnow() - user.created_at).total_seconds() / 86400.0 if user and user.created_at else 0.0
    bought = bool(user and OrderItem.query.join(Order).filter(Order.user_id == user.id, OrderItem.sku == sku).first())
    device = ctx.cookies.get("did") or f"sid-{ctx.session.sid}"
    d_key, i_key = f"lab:rv:dev:{device}", f"lab:rv:ip:{ctx.ip}"
    by_device, by_ip = ctx.redis.incr(d_key), ctx.redis.incr(i_key)
    ctx.redis.expire(d_key, 86400)
    ctx.redis.expire(i_key, 3600)
    return {"account_age_days": age, "verified_purchase": bought,
            "reviews_by_device_24h": by_device, "reviews_by_ip_1h": by_ip}


def _check(ctx):
    f = facts(ctx)
    # TODO (Round 1):
    #   1. reviews_by_device_24h > DEVICE_CAP_24H -> block   (one device, many "customers")
    #   2. reviews_by_ip_1h      > IP_CAP_1H      -> block   (one egress, many "customers")
    #   3. not verified_purchase and account_age_days < NEW_ACCOUNT_DAYS -> hold for moderation
    return None


CHECK = Check("review_signals", _check, phases=("action:review",))
