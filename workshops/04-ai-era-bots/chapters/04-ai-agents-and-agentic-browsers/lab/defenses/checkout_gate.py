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
    # TODO (Round 4): three rules, in this order.
    #   a. "declared_agent": return (0, []), {}  -- L1 already refuses them.
    #   b. "verified_agent": ctx["mandate"] is None -> (60, [reason]), {"needs": "mandate"};
    #      mandate_problems(...) non-empty -> (60, [...]), {"needs": "mandate"};
    #      else extra["mandate_ok"] = mandate.id and fall through to the caps.
    #   c. anyone else, unless ctx["step_up_confirmed"]: if ctx["behavior_points"] >= SUSPECT_AT
    #      or the account is < NEW_ACCOUNT_DAYS old with no prior orders -> +30 and
    #      extra["step_up"] = True (the app emails a code and replies 202).
    #   Caps for every principal: ctx["account_units"] >= PER_ACCOUNT_CAP -> +60;
    #   ctx["device_units"] >= PER_DEVICE_CAP -> +60.
    # Until then the gate lets every checkout through unchanged.
    return (points, reasons), extra

if __name__ == '__main__':
    from datetime import datetime
    now = datetime.now(timezone.utc)
    human = {"id": 1, "account_age_days": 400, "prior_orders": 3}
    print(evaluate({"kind": "human"}, human, {}, {"sku": "lab-runner-9", "behavior_points": 0, "now": now}))
    print(evaluate({"kind": "human"}, human, {}, {"sku": "lab-runner-9", "behavior_points": 45, "now": now}))
    print(evaluate({"kind": "verified_agent", "operator": "agents.lab-provider.test"}, human, {},
                   {"sku": "lab-runner-9", "mandate": None, "behavior_points": 45, "now": now}))
