"""
W4 Ch4, L4 the checkout gate: bind the purchase to a principal (Round 4)

Everything before this layer answers "who or what is this session?". The gate answers the question
the business actually has: *may this purchase happen, and who stands behind it?* Three rules,
cheapest first:

    verified agent     needs a MANDATE from the account holder: a scoped, time-boxed, single-use
                       approval for (this operator, this SKU, this quantity). Modelled on AP2's
                       intent / cart mandates and the card networks' agentic tokens (2025-2026).
                       No mandate -> block.
    everyone else      a STEP-UP (a one-time code to the account's email) when the session looks a
                       little robotic (behavior points >= SUSPECT_AT) or the account is brand new
                       with no history. This is the hand-off every agentic browser already does at
                       payment: stop and ask the human.
    any principal      a per-DEVICE cap on the protected drop. A fleet of fresh browser contexts on
                       one machine shares one fingerprint, so it shares one cap. (The per-ACCOUNT
                       cap is the store's own: `max_per_account` on the drop.)

The gate is a check, so it answers with the closed verdict set: a missing mandate or a full device
is a `block` (points >= 60), a step-up is the `step_up` challenge (30). What happens after a purchase
that passed (spending the mandate, counting the device, stamping the order with the operator and the
mandate) is demo_site/ext/agents.py's `hooks.on_action("drop_buy", ...)`.

False positives: the first-time buyer who registers during the drop gets a step-up (friction, not
refusal); a household buying on two identical laptops behind one fingerprint would meet the device
cap. What the gate cannot do: tell a fleet that owns twelve inboxes and randomises twelve
fingerprints from twelve people. That fight is W2 Ch2 (fingerprint stability) and the plain
economics of owning twelve of everything, and it costs the attacker twelve of everything.
"""

import time
from datetime import datetime, timezone

from . import agent_session, mandates
from .pipeline import Check, Signal

PROTECTED_SKU = "lab-runner-9"      # the limited drop the caps protect; other drops get the step-up only
SUSPECT_AT = 20
NEW_ACCOUNT_DAYS = 1
PER_DEVICE_CAP = 2


def mandate_problems(mandate, user, operator, sku, now):
    problems = []
    if user is None or mandate["user_id"] != user["id"]:
        problems.append("mandate belongs to another account")
    if mandate["operator"] != operator:
        problems.append(f"mandate is for operator {mandate['operator']}, request is from {operator}")
    if mandate["sku"] != sku:
        problems.append(f"mandate is for {mandate['sku']}, the order is for {sku}")
    if mandate["used_at"] is not None:
        problems.append("mandate already used")
    if mandate["expires_at"] < now:
        problems.append("mandate expired")
    return problems


def evaluate(principal, user, gate):
    """
    Returns ((points, reasons), extra). extra tells the rest of the store what happened:
        {"step_up": True}          the step_up challenge (a 30-point signal)
        {"needs": "mandate"}       the agent must obtain a mandate from its user
        {"mandate_ok": <id>}       spend this mandate when the order is placed
    user: {"id", "account_age_days", "prior_orders"} or None (a guest)
    gate keys: sku, mandate (dict or None), behavior_points, device_units (protected drop units this
               device bought in 24 h), now (epoch seconds)
    """
    points, reasons, extra = 0, [], {}
    kind = principal["kind"]
    if kind == "declared_agent":
        return (0, []), {}                      # Round 1 already refuses them
    if kind == "verified_agent":
        mandate = gate.get("mandate")
        if mandate is None:
            return (60, ["A verified agent needs a mandate from the account holder (X-Agent-Mandate or the mandate field)"]), {"needs": "mandate"}
        problems = mandate_problems(mandate, user, principal["operator"], gate["sku"], gate["now"])
        if problems:
            return (60, ["Mandate refused: " + "; ".join(problems)]), {"needs": "mandate"}
        extra["mandate_ok"] = mandate["id"]
    else:
        fresh = user is not None and user["account_age_days"] < NEW_ACCOUNT_DAYS and user["prior_orders"] == 0
        if gate["behavior_points"] >= SUSPECT_AT or fresh:
            points += 30
            reasons.append("Step-up: " + ("a brand-new account with no history" if fresh
                                          else f"the session looks robotic ({gate['behavior_points']} behavior points)"))
            extra["step_up"] = True
    if gate["sku"] == PROTECTED_SKU and gate["device_units"] >= PER_DEVICE_CAP:
        points += 60
        reasons.append(f"This device already bought {gate['device_units']} unit(s) of the drop in 24 h (cap {PER_DEVICE_CAP})")
    return (points, reasons), extra


def _mandate_id(ctx):
    for body in (ctx.form, ctx.json):
        if isinstance(body, dict) and body.get("mandate"):
            return str(body["mandate"]).strip()
    return ctx.header("X-Agent-Mandate")


def _account(ctx):
    if ctx.user is None:
        return None
    created = ctx.user.created_at
    age = (datetime.now(timezone.utc).replace(tzinfo=None) - created).total_seconds() / 86400 if created else 9999.0
    return {"id": ctx.user.id, "account_age_days": age, "prior_orders": len(ctx.user.orders)}


def _facts(ctx):
    """What the gate needs to know about this order. Given: the cheap lookups."""
    # A device is its browser fingerprint (the same machine, however many fresh cookie jars); a client
    # that sent no telemetry falls back to its device cookie, then to its address.
    device = agent_session.device_key(ctx)
    return _account(ctx), {
        "sku": ctx.notes.get("sku", ""), "mandate": mandates.get(ctx.redis, _mandate_id(ctx)), "now": time.time(),
        "behavior_points": ctx.attrs.get("behavior_points", 0), "device": device,
        "device_units": int(ctx.redis.get(f"{agent_session.DEVICE_PREFIX}{device}") or 0)}


def _check(ctx):
    from . import principal as who      # principal.py imports the Round 1 and 3 modules: import it late
    user, gate = _facts(ctx)
    (points, reasons), extra = evaluate(who.principal(ctx), user, gate)
    if extra.get("mandate_ok"):
        ctx.attrs["mandate_ok"] = extra["mandate_ok"]
    ctx.note(gate=dict(extra), device=str(gate["device"])[:16])
    name = "needs_mandate" if extra.get("needs") else ("cap" if points >= 60 else "step_up")      # what decided it
    return [Signal("checkout_gate", name, points, "; ".join(reasons)[:140])] if points else None


CHECK = Check("checkout_gate", _check, phases=("action:drop_buy",))
