"""
Chapter 9 — Risk engine: one score, three outcomes (Sections 9.1, 9.4)

Workshop 2 used a different scoring scale in almost every chapter. The
capstone settles on one, the additive 0–100 scale from W2 Ch8:

    score <  30   allow
    score 30–59   challenge   (step-up: CAPTCHA, emailed code, queue)
    score >= 60   block

Each layer returns (points, [reasons]). A layer is enabled when
DEFENSE_LEVEL >= its level. Disabled layers still run in *shadow mode*: their
points go into decision["shadow"] and the decisions table, but not into the
score. That is how you would roll out a new layer in production: measure what
it would have done to real traffic before it can hurt anyone.

    Level  Tag  Where           Module
    0      L0   every request   request_checks (headers, rate), tls_consistency (JA4 vs. UA)
    0      L0   buy             automation (webdriver, automation globals, missing telemetry)
    1      L1   buy             fingerprint_coherence
    2      L2   buy             behavior_flow
    3      L3   buy             session_model (needs tools/train_model.py)
    4      L4   login           token_binding, login_risk
    5      L5   api             api_hardening (GraphQL cost/introspection, JWT-JA4 bind, REST velocity)  [W3 Ch2]
    6      L6   buy/login/api   streaming.aggregator (rate, regularity, navigation, fed by the bus)      [W3 Ch3]
    7      L7   buy             supply_chain (CSP/SRI violation reports on this session)                  [W3 Ch5]

Levels 0-4 are the Workshop 1+2 stack you already built; the capstone
ships them on. Levels 5-7 are the Workshop 3 "detection at scale" layers added
in the lab's Rounds 1-3. Round 4 runs every level at once.

Why additive points and not a probability (noisy-OR, W2 Ch1)? Points are
easy to read in a reason list and easy to tune in a lab. The cost is that
correlated signals double-count: a headless browser trips several L1 checks
for one root cause. The L3 model learns those correlations instead of adding
them up.
"""

import api_hardening
import automation
import behavior_flow
import fingerprint_coherence
import login_risk
import request_checks
import session_model
import supply_chain
import tls_consistency
import token_binding
from streaming import aggregator as stream_agg

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
    shadow = {}
    for min_level, tag, (points, why) in layers:
        if level >= min_level:
            score += points
            reasons.extend(f"[{tag}] {r}" for r in why)
        elif points:
            shadow[tag] = {"points": shadow.get(tag, {}).get("points", 0) + points,
                           "reasons": shadow.get(tag, {}).get("reasons", []) + why}
    score = min(score, 100)
    return {"score": score, "outcome": outcome_for(score), "reasons": reasons, "shadow": shadow}


def score_request(ctx, store, level, count=True):
    """L0 checks that need only the HTTP request and the TLS fingerprint."""
    return combine([
        (0, "L0", request_checks.score_headers(ctx)),
        (0, "L0", tls_consistency.score_tls(ctx)),
        (0, "L0", request_checks.score_rate(ctx, store, count=count)),
    ], level)


def evaluate_buy(request_decision, sess, user, level, model, store=None):
    l0 = automation.score_automation(sess)
    l1 = fingerprint_coherence.score_coherence(sess["fp"], sess.get("http_ua"))
    l2 = behavior_flow.score_behavior(sess)
    features = session_model.build_features(sess, user, l1[0], l2[0])
    l3 = session_model.score_session(features, model)
    l6 = stream_agg.score_stream(store, sess.get("sid")) if store is not None else (0, [])
    l7 = supply_chain.score_violations(store, sess.get("sid")) if store is not None else (0, [])
    decision = combine([(0, "L0", l0), (1, "L1", l1), (2, "L2", l2), (3, "L3", l3),
                        (6, "L6", l6), (7, "L7", l7)],
                       level, base=request_decision)
    decision["features"] = features
    return decision


def evaluate_login(request_decision, sess, token_ok, cluster, store, level):
    l6 = stream_agg.score_stream(store, sess.get("sid"))
    decision = combine([
        (4, "L4", token_binding.score_token(token_ok)),
        (4, "L4", login_risk.score_cluster(store, cluster)),
        (6, "L6", l6),
    ], level, base=request_decision)
    decision["features"] = {"token_ok": token_ok, "cluster": login_risk.cluster_id(cluster)}
    return decision


def evaluate_api(request_decision, analysis, token_state, store, cluster, sid, level):
    """Score a GraphQL/REST API call (L5) plus the streaming verdict (L6).
    analysis: the GraphQL analyze_body() dict, or None for a REST call.
    token_state: (ok, why) from api_auth.verify, or None when the route is public.
    cluster: the fingerprint-cluster key for REST velocity, or None for GraphQL."""
    layers = []
    if analysis is not None:
        layers.append((5, "L5", api_hardening.score_graphql(analysis)))
    if token_state is not None:
        layers.append((5, "L5", api_hardening.score_token(*token_state)))
    if cluster is not None:
        layers.append((5, "L5", api_hardening.rest_velocity(store, cluster)))
    layers.append((6, "L6", stream_agg.score_stream(store, sid)))
    return combine(layers, level, base=request_decision)


def stream_agg_cv(store, sid):
    """The current inter-request CV for a session (for /whoami and signalhealth.py)."""
    from streaming import detectors
    return detectors.cv_for(store, sid)


def tls_family(ctx):
    return tls_consistency.tls_family(ctx)


def impersonate_hint(ua):
    """Which curl_cffi profile best matches a captured browser (for legit_traffic.py)."""
    family = tls_consistency.ua_family(ua)
    if family == "safari":
        return "safari_ios" if ("iPhone" in ua or "iPad" in ua) else "safari"
    return family if family in ("chrome", "firefox") else "chrome"


if __name__ == '__main__':
    for s in (0, 25, 30, 59, 60, 100):
        print(s, outcome_for(s))
