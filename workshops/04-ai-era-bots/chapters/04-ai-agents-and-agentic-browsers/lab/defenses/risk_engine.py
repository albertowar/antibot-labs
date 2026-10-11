"""
W4 Ch4 — Risk engine: one score, three outcomes, and a principal

Same scale as W2 Ch8/Ch9 so nothing has to be relearned:

    score <  30   allow
    score 30–59   challenge   (here: hand the decision back to a human — an emailed code)
    score >= 60   block

Layers return (points, [reasons]) and are enabled when DEFENSE_LEVEL >= their
level. Disabled layers run in *shadow mode*: their points land in
decision["shadow"] and in the decisions table but not in the score.

    Level  Tag  Where      Module             Round
    0      L0   request    request_checks     (headers, per-egress rate; W1)
    1      L1   checkout   agent_policy       1  declared agents: browse yes, buy no
    2      L2   checkout   agent_behavior     2  how the session acts (challenge, never block)
    3      L3   checkout   agent_identity     3  claimed identity that doesn't verify
    4      L4   checkout   checkout_gate      4  mandates, step-up, per-account/device caps
    —      W2   checkout   automation + fingerprint_coherence + behavior_flow, ALWAYS shadow

Why is the W2 stack shadow-only here? W2 Ch9 ended with that stack beaten by
patched and native-stealth browsers. An agent that drives the user's own
Chrome is beyond it by construction: real GPU, real window, real TLS, real
IP. We keep it running so you can *see* that: the scoreboard prints the W2
points for agents next to humans.

Why does L2 stop adding points at L4? At L4 the behavior score becomes an
*input* to the checkout gate (which decides between allow, step-up and
block) instead of a verdict of its own. Two challenge-band layers would
otherwise add up to a block for a nervous human.
"""

import agent_behavior
import agent_identity
import agent_policy
import automation
import behavior_flow
import checkout_gate
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


def evaluate_checkout(request_decision, sess, user, principal, identity, gate_ctx, level):
    """
    The one decision that matters in this chapter. Inputs:
        sess        telemetry + flow for this session (app.session_state)
        user        the account (app.user_state)
        principal   agent_policy.classify(...) possibly upgraded to verified_agent by the app
        identity    agent_identity.verify(...)
        gate_ctx    what checkout_gate needs: sku, mandate id, store, device key, behavior points
    """
    l1 = agent_policy.score_checkout(principal)
    # Identity replaces inference: once we know who operates the agent we stop guessing from its hands.
    l2 = agent_behavior.score(sess) if principal["kind"] != "verified_agent" else (0, [])
    l3 = agent_identity.score(identity)
    gate_ctx = dict(gate_ctx, behavior_points=l2[0])
    l4, extra = checkout_gate.evaluate(principal, user, sess, gate_ctx)
    l2_counted = l2 if level < 4 else (0, [])
    decision = combine([(1, "L1", l1), (2, "L2", l2_counted), (3, "L3", l3), (4, "L4", l4)],
                       level, base=request_decision)
    decision["shadow"]["W2"] = dict(zip(("points", "reasons"), w2_shadow(sess)))
    decision["features"] = {
        "principal": principal["kind"], "operator": principal.get("operator"),
        "identity": identity["status"], "behavior": agent_behavior.features(sess),
        "behavior_points": l2[0], "gate": extra,
    }
    decision["extra"] = extra
    return decision


if __name__ == '__main__':
    for s in (0, 25, 30, 59, 60, 100):
        print(s, outcome_for(s))
