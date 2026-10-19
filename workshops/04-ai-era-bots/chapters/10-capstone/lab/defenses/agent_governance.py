"""
W4 Ch10 Capstone — L2 agent governance: the Ch8 policy, live at checkout (YOUR CODE, Round 2)

The store already knows (GIVEN, W4 Ch4): who claims to be an agent
(agent_policy), whether a Web Bot Auth signature verifies (agent_identity), how
the session behaved (agent_behavior), and the W4 Ch8 signal row
(signals.derive). This module turns policies/agent_policy.json into the checkout
decision.

evaluate(policy, row, principal, identity, ustate, ctx) -> ((points, reasons), extra)
    row    signals.derive(): signals, client, declared, robotic, a11y, features
    ctx    sku, mandate, now, orders_last_hour, device_units, account_units,
           step_up_confirmed, challenge_solved
    extra  {"challenge": kind} | {"step_up": True} | {"needs": "mandate"} | {"mandate_ok": id}

Three TODOs:
  2a  challenge_kind(policy, row): the policy says challenge_type; the assistive
      cohort needs a non-visual path whatever it says.
  2b  needs_human_confirm(policy, row, ustate): honour "human_confirm" for
      agent-class clients, new accounts and robotic sessions, not plain shoppers.
  2c  policies/agent_policy.json: starts blunt (hard-blocks agent_ua /
      signature_agent / no_pointer, image CAPTCHA). Run the farm and the legit
      mix, read who it refuses, rewrite it (Ch8 Round 2 is the map).

`tools/checkpoint.py --round 2 --catch-up` drops in the reference module AND policy.
"""

from . import policy_engine

PER_ACCOUNT_CAP = 1
PER_DEVICE_CAP = 1


def challenge_kind(policy, row):
    # TODO (Round 2a): give screen_reader_api sessions a non-visual challenge.
    return policy["challenge_type"]


def needs_human_confirm(policy, row, ustate):
    # TODO (Round 2b): honour policy["checkout_step_up"] == "human_confirm" for
    # agent-class clients, new accounts and robotic sessions.
    return False


def _mandate_problems(mandate, ustate, operator, sku, now):
    problems = []
    if mandate.user_id != ustate["id"]:
        problems.append("mandate belongs to another account")
    if mandate.operator != operator:
        problems.append(f"mandate is for operator {mandate.operator}, request is from {operator}")
    if mandate.sku != sku:
        problems.append(f"mandate is for {mandate.sku}, cart holds {sku}")
    if mandate.used_at is not None:
        problems.append("mandate already used")
    exp = mandate.expires_at if mandate.expires_at.tzinfo else mandate.expires_at.replace(tzinfo=now.tzinfo)
    if exp < now:
        problems.append("mandate expired")
    return problems


def evaluate(policy, row, principal, identity, ustate, ctx):
    """GIVEN: compose the policy verdict with the W4 Ch4 identity and mandate checks."""
    points, reasons, extra = 0, [], {}
    prow = {"signals": row["signals"], "client": row["client"], "declared": row["declared"],
            "orders_per_hour": ctx.get("orders_last_hour", 0)}
    action, why, score = policy_engine.decide(prow, policy)
    extra.update(action=action, reason=why, policy_score=score)

    if identity["status"] not in ("none", "verified"):
        return (60, [f"Claimed agent identity did not verify ({identity['status']}): " + "; ".join(identity["reasons"])]), \
            dict(extra, action="block")

    if principal["kind"] == "verified_agent":
        mandate = ctx.get("mandate")
        if mandate is None:
            return (60, ["Verified agent without a mandate: the account holder must approve this purchase "
                         "(POST /api/account/mandates from their own session)"]), dict(extra, needs="mandate", action="block")
        problems = _mandate_problems(mandate, ustate, principal["operator"], ctx["sku"], ctx["now"])
        if problems:
            return (60, [f"Mandate rejected: {p}" for p in problems]), dict(extra, needs="mandate", action="block")
        extra["mandate_ok"] = mandate.id

    if action == "block":
        points += 60
        reasons.append(f"Policy '{policy.get('name')}' blocks: {why} (signals {', '.join(row['signals']) or 'none'})")
    elif action == "challenge" and not ctx.get("challenge_solved"):
        points += 30
        kind = challenge_kind(policy, row)
        reasons.append(f"Policy '{policy.get('name')}' challenges ({kind}): {why}")
        extra["challenge"] = kind
    elif principal["kind"] != "verified_agent" and not ctx.get("step_up_confirmed") \
            and needs_human_confirm(policy, row, ustate):
        points += 30
        reasons.append(f"Step-up: a person must confirm this order ({row['client']}, "
                       f"{'new account' if 'new_account' in row['signals'] else 'policy'})")
        extra["step_up"] = True

    if ctx.get("account_units", 0) >= PER_ACCOUNT_CAP:
        points += 60
        reasons.append(f"Account already holds {ctx['account_units']} drop unit(s) (cap {PER_ACCOUNT_CAP})")
    if ctx.get("device_units", 0) >= PER_DEVICE_CAP:
        points += 60
        reasons.append(f"Device {str(ctx.get('device_key', '?'))[:12]}… already bought {ctx['device_units']} "
                       f"drop unit(s) in 24 h (cap {PER_DEVICE_CAP})")
    return (points, reasons), extra
