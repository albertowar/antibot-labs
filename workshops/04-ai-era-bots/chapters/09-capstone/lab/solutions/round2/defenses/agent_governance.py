"""
W4 Ch9 Capstone — L2 agent governance (REFERENCE SOLUTION, Round 2)

Same GIVEN composition as the stub; the three TODOs resolved:

  2a  challenge_kind: a session that shows screen_reader_api gets a proof of
      work whatever challenge_type says. An image CAPTCHA served to a
      screen-reader user is a block with extra steps (W4 Ch8 §8.2.3), and the
      scoreboard counts it as one. Everyone else gets the policy's kind.
  2b  needs_human_confirm: when the policy says human_confirm, the emailed
      code goes to every agent-class client (local, cloud, assistive), every
      brand-new account and every robotic session. A plain shopper on an aged
      account never sees it. A shopper's agent hands the code back to the
      shopper; an unattended farm fails here; a farm with a human operator
      passes it and meets the velocity rule and the device cap instead.
  2c  the policy JSON: solutions/round2/policies/agent_policy.json (nothing blocked
      for being an agent; weights on fp_reuse and new_account; declare or
      take a proof of work; four orders an hour per account; appeal path on;
      90-day retention).
"""

import policy_engine

PER_ACCOUNT_CAP = 1
PER_DEVICE_CAP = 1


def challenge_kind(policy, row):
    if "screen_reader_api" in row["signals"]:
        return "pow"
    return policy["challenge_type"]


def needs_human_confirm(policy, row, ustate):
    if policy.get("checkout_step_up") != "human_confirm":
        return False
    fresh = ustate["account_age_days"] < 1 and ustate["prior_orders"] == 0
    return row["client"] in policy_engine.AGENT_CLIENTS or fresh or row["robotic"]


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
