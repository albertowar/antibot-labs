"""
Round 1 defense (REFERENCE SOLUTION): content-independent review signals.

Why this works when text analysis stops working: a review farm's economics force it to (a) use accounts it
created recently and cheaply, (b) skip buying the product (a verified purchase costs the attacker real
money per review), and (c) reuse devices and egress. None of those show up in the prose, and an LLM cannot
write them away.

Decisions, in order:
  1. Device velocity: more than DEVICE_CAP_24H reviews from one device cookie in a day -> BLOCK.
     Households share a device, so the cap is generous, not 1.
  2. Egress velocity: more than IP_CAP_1H reviews from one IP in an hour -> BLOCK. CGNAT and campus NATs
     put thousands of people behind one IP; keep this cap high and, in production, scope it per /24 or ASN.
  3. Unverified purchase from a young account -> HOLD for moderation. Not a block: a brand-new real
     customer who bought elsewhere and wants to warn others is a legitimate reviewer, and a hold is
     recoverable.

False positives, named honestly: the hold in (3) catches real people who review a gift, or who bought
in-store. Measure how many held reviews a moderator later approves; if it is most of them, the hold is
costing you reviews for nothing. And the device cookie is only as good as the attacker's cookie jar:
clearing it resets the count (the device fingerprint of W2 Ch2 is the answer, and it has its own costs).
"""

from .pipeline import Check, Signal, Verdict

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
    if f["reviews_by_device_24h"] > DEVICE_CAP_24H:
        return Verdict("block", signals=(Signal("review_signals", "device_velocity", 90,
                                                f"{f['reviews_by_device_24h']} reviews/24h from one device"),))
    if f["reviews_by_ip_1h"] > IP_CAP_1H:
        return Verdict("block", signals=(Signal("review_signals", "ip_velocity", 85,
                                                f"{f['reviews_by_ip_1h']} reviews/h from one egress IP"),))
    if not f["verified_purchase"] and f["account_age_days"] < NEW_ACCOUNT_DAYS:
        ctx.attrs["review_hold"] = "unverified purchase from a new account"
        return [Signal("review_signals", "new_unverified", 10, f"{f['account_age_days']:.1f} days old, no purchase")]
    return None


CHECK = Check("review_signals", _check, phases=("action:review",))
