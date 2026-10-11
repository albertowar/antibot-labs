"""
W4 Ch9 Capstone — Risk engine: one score, three outcomes, five levels (GIVEN)

Same scale as W2 Ch8 / W4 Ch4 so nothing has to be relearned:

    score <  30   allow
    score 30–59   challenge   (a proof of work, an image puzzle, or a code a person answers)
    score >= 60   block

Layers return (points, [reasons]) and count when DEFENSE_LEVEL >= their level.
Below that they run in SHADOW: their points land in decision["shadow"] and in
the decisions table, never in the score. That is how Round 0 shows you what
the whole W4 stack *would* have said before any of it is switched on.

    Level  Tag  Where      Module              Round
    0      L0   request    request_checks      W1: headers, per-egress rate
    1      L1   content    crawl_governance    1  identity × purpose: allow / charge / 402 / maze / block
    2      L2   checkout   agent_governance    2  the Ch8 policy, live; identity, mandates, caps
    3      L3   content    deception_limits    3  traps only to refused traffic; llm_guard on /summary, /assist
    4      L4   checkout   rules (approved)    4  human-approved rules; oracle_guard shapes every reply
    —      W2   checkout   automation + fingerprint_coherence + behavior_flow, ALWAYS shadow

L1 and L3 act on content responses and are applied by the store directly;
this module scores requests and checkouts.
"""

import agent_behavior
import agent_governance
import automation
import behavior_flow
import fingerprint_coherence
import request_checks

ALLOW_BELOW = 30
BLOCK_AT = 60


def outcome_for(score):
    if score >= BLOCK_AT:
        return "block"
    if score >= ALLOW_BELOW:
        return "challenge"
    return "allow"


def combine(layers, level, base=None):
    """layers: [(min_level, tag, (points, reasons))]. Returns a decision dict."""
    score = base["score"] if base else 0
    reasons = list(base["reasons"]) if base else []
    shadow = dict(base.get("shadow", {})) if base else {}
    for min_level, tag, (points, why) in layers:
        if level >= min_level:
            score += points
            reasons.extend(f"[{tag}] {r}" for r in why)
        elif points:
            prev = shadow.get(tag, {"points": 0, "reasons": []})
            shadow[tag] = {"points": prev["points"] + points, "reasons": prev["reasons"] + list(why)}
    score = min(score, 100)
    return {"score": score, "outcome": outcome_for(score), "reasons": reasons, "shadow": shadow}


def score_request(ctx, store, level, count=True):
    """L0: headers and per-egress rate. Runs on every request."""
    return combine([
        (0, "L0", request_checks.score_headers(ctx)),
        (0, "L0", request_checks.score_rate(ctx, store, count=count)),
    ], level)


def w2_shadow(sess):
    """What the end-of-W2 stack would have said about this checkout. Never counts."""
    points, reasons = 0, []
    for fn in (lambda: automation.score_automation(sess),
               lambda: fingerprint_coherence.score_coherence(sess["fp"], sess.get("http_ua")),
               lambda: behavior_flow.score_behavior(sess)):
        p, r = fn()
        points += p
        reasons.extend(r)
    return points, reasons


def session_card(row, ustate, ctx, ua, egress_kind, fp_accounts):
    """The flat dict the rule engine (L4) evaluates. Same fields as rules.RULE_FIELDS."""
    return {
        "client": row["client"], "egress_kind": egress_kind, "ua": ua, "declared": row["declared"],
        "signals": list(row["signals"]), "orders_per_hour": ctx.get("orders_last_hour", 0),
        "account_age_days": round(ustate["account_age_days"], 3), "prior_orders": ustate["prior_orders"],
        "fp_accounts": fp_accounts, "behavior_points": row["behavior_points"],
    }


def evaluate_checkout(request_decision, sess, ustate, principal, identity, row, ctx, level, policy,
                      rule_engine=None, card=None):
    """
    The one decision that matters in this chapter.
        sess        telemetry + flow for this session (app.session_state)
        ustate      the account (app.user_state)
        principal   agent_policy.classify(...) possibly upgraded to verified_agent
        identity    agent_identity.verify(...)
        row         signals.derive(...): the W4 Ch8 signal row for this checkout
        ctx         sku, mandate, now, orders_last_hour, device/account units, confirmations
        policy      policy_engine.load_policy()
        rule_engine rules.RuleEngine or None; card = session_card(...)
    """
    l2, extra = agent_governance.evaluate(policy, row, principal, identity, ustate, ctx)
    layers = [(2, "L2", l2)]
    rule_hit = None
    if rule_engine is not None and card is not None:
        rule_hit, shadow_rules, _ms = rule_engine.evaluate(card)
        if rule_hit:
            conds = " AND ".join(f"{c['field']} {c['op']} {c['value']!r}" for c in rule_hit["when"]["all"])
            layers.append((4, "L4", (60, [f"approved rule {rule_hit.get('id')}: {conds}"])))
    decision = combine(layers, level, base=request_decision)
    decision["shadow"]["W2"] = dict(zip(("points", "reasons"), w2_shadow(sess)))
    decision["features"] = {
        "principal": principal["kind"], "operator": principal.get("operator"), "identity": identity["status"],
        "client": row["client"], "signals": row["signals"], "behavior": row["features"],
        "behavior_points": row["behavior_points"], "policy": extra, "rule": rule_hit.get("id") if rule_hit else None,
    }
    decision["extra"] = extra
    return decision


if __name__ == '__main__':
    for s in (0, 25, 30, 59, 60, 100):
        print(s, outcome_for(s))
