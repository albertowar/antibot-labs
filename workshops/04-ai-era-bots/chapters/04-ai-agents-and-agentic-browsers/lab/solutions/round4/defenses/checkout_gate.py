"""
W4 Ch4 — L4 the checkout gate: bind the purchase to a principal (Round 4)

Everything before this layer answers "who or what is this session?". The
gate answers the question the business actually has: *may this purchase
happen, and who stands behind it?* Three rules, cheapest first:

    verified agent     needs a MANDATE from the account holder: a scoped, time-boxed,
                       single-use approval for (this operator, this SKU, this quantity).
                       Modelled on AP2's intent/cart mandates and the card networks'
                       agentic tokens (2025–2026). No mandate -> block, with the hint
                       the agent needs to go and ask its user.
    everyone else      a STEP-UP (one-time code to the account's email) when the session
                       looks a little robotic (behavior points >= SUSPECT_AT) or the account
                       is brand new with no history. This is the hand-off every agentic
                       browser already does at payment: stop and ask the human.
    any principal      per-ACCOUNT cap (one drop unit) and per-DEVICE cap: a device that has
                       never checked out before is keyed by its fingerprint hash, a known
                       device by its cookie. A fleet of fresh contexts on one machine shares
                       one fingerprint -> one unit.

False positives: the first-time buyer who registers during the drop gets a
step-up (friction, not refusal); a household buying on two identical laptops
behind one fingerprint would hit the device cap if neither had a cookie yet.
What the gate cannot do: distinguish a fleet that owns twelve inboxes and
randomises twelve fingerprints from twelve people. That fight is W2 Ch4/Ch9
(fingerprint stability) and W3 Ch6 (account economics), and it costs the
attacker twelve of everything.
"""

from datetime import timezone

SUSPECT_AT = 20
NEW_ACCOUNT_DAYS = 1
PER_ACCOUNT_CAP = 1
PER_DEVICE_CAP = 1


def _aware(dt):
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def mandate_problems(mandate, user, operator, sku, now):
    problems = []
    if mandate.user_id != user["id"]:
        problems.append("mandate belongs to another account")
    if mandate.operator != operator:
        problems.append(f"mandate is for operator {mandate.operator}, request is from {operator}")
    if mandate.sku != sku:
        problems.append(f"mandate is for {mandate.sku}, cart holds {sku}")
    if mandate.used_at is not None:
        problems.append("mandate already used")
    if _aware(mandate.expires_at) < now:
        problems.append("mandate expired")
    return problems


def evaluate(principal, user, sess, ctx):
    """
    Returns ((points, reasons), extra). extra tells the app what to do next:
        {"step_up": True}          send a code, reply 202 (challenge)
        {"needs": "mandate"}       the agent must obtain a mandate from its user
        {"mandate_ok": <id>}       consume this mandate when the order is placed
    ctx keys: sku, mandate (Mandate row or None), behavior_points, step_up_confirmed,
              device_units (drop units this device bought in 24 h), account_units, now
    """
    points, reasons, extra = 0, [], {}
    kind = principal["kind"]

    if kind == "declared_agent":
        return (0, []), extra  # L1 already refuses unverified declared agents

    if kind == "verified_agent":
        mandate = ctx.get("mandate")
        if mandate is None:
            return (60, ["Verified agent without a mandate: the account holder must approve this purchase "
                         "(POST /api/account/mandates from their own session)"]), {"needs": "mandate"}
        problems = mandate_problems(mandate, user, principal["operator"], ctx["sku"], ctx["now"])
        if problems:
            return (60, [f"Mandate rejected: {p}" for p in problems]), {"needs": "mandate"}
        extra["mandate_ok"] = mandate.id
    elif not ctx.get("step_up_confirmed"):
        robotic = ctx.get("behavior_points", 0) >= SUSPECT_AT
        fresh = user["account_age_days"] < NEW_ACCOUNT_DAYS and user["prior_orders"] == 0
        if robotic or fresh:
            why = "session acts like automation" if robotic else "new account with no purchase history"
            points += 30
            reasons.append(f"Step-up: {why}; a one-time code was sent to the account's email")
            extra["step_up"] = True

    if ctx.get("account_units", 0) >= PER_ACCOUNT_CAP:
        points += 60
        reasons.append(f"Account already holds {ctx['account_units']} drop unit(s) (cap {PER_ACCOUNT_CAP})")
    if ctx.get("device_units", 0) >= PER_DEVICE_CAP:
        points += 60
        reasons.append(f"Device {ctx.get('device_key', '?')[:12]}… already bought {ctx['device_units']} drop unit(s) "
                       f"in 24 h (cap {PER_DEVICE_CAP})")
    return (points, reasons), extra


if __name__ == '__main__':
    from datetime import datetime
    now = datetime.now(timezone.utc)
    human = {"id": 1, "account_age_days": 400, "prior_orders": 3}
    print(evaluate({"kind": "human"}, human, {}, {"sku": "lab-runner-9", "behavior_points": 0, "now": now}))
    print(evaluate({"kind": "human"}, human, {}, {"sku": "lab-runner-9", "behavior_points": 45, "now": now}))
    print(evaluate({"kind": "verified_agent", "operator": "agents.lab-provider.test"}, human, {},
                   {"sku": "lab-runner-9", "mandate": None, "behavior_points": 45, "now": now}))
