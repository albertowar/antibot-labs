"""
Policy: how the layers' signals become one answer, and what the operator may change

The layers (sensors.py, correlation.py, campaign.py, model.py, containment.py) only report
signals. This file decides what to do with them:

    score <  CHALLENGE_AT              allow
    CHALLENGE_AT <= score < BLOCK_AT   challenge   a proof of work (DEFAULT_CHALLENGE)
    score >= BLOCK_AT                  block       answered as "Wrong email or password" (deceive)
    hot campaign cluster / contained ASN   a step-up code, unless the score already blocks

The numbers below are the *deploy-time* policy. The operator's overrides live in
data/ops_config.json (defenses/config.py, resolved per request by defenses/ops.py) and win at
request time, so a weight can go to zero (a kill switch) or up (a burned signal's replacement)
without a restart. `tools/configure.py` writes them; `tools/sweep.py` replays last week's log
against them first.

Why a ladder instead of a yes/no:
- One weak signal (a VPN, a password manager) costs a real user nothing.
- Several weak signals together add up to a block even though no layer is sure by itself.
- The middle band buys certainty with friction instead of with a block. A challenge is a *cost*,
  not a verdict: humans pay it in seconds, bots in CPU. It stops lazy bots and only slows
  determined ones.

Weights are a statement about how much you trust each signal, and about the people each one hurts
by mistake. Write them down next to their false positives, and change them with data
(tools/sweep.py), not with feelings.

The known-good cohort (allowlist.py) is scored like everyone else and served: `decide` returns
`monitor` for it and notes what the decision would have been (`would_be`).
"""

# TODO (Round 1): read every weight next to the false-positive notes in sensor_*.py. A weight of 0
# is a kill switch; raising one to cover for a burned signal borrows against the false-positive
# budget. Try `python tools/sweep.py --weight header_order_mismatch=0` and see who moves.
WEIGHTS = {
    # network (W1 Ch3)
    "ip_blocklist": 60,
    "tor_exit": 30,      # 40 blocks every Tor Browser user (sweep.py --signal tor_exit)
    "datacenter_asn": 25,
    # headers (W1 Ch4)
    "http_library_ua": 60,
    "missing_browser_headers": 30,
    "header_order_mismatch": 10,
    "outdated_browser": 10,
    # TLS (W2 Ch3)
    "ja4_non_browser": 50,
    "ja4_ua_mismatch": 30,
    # velocity (W1 Ch2)
    "ip_burst": 30,
    "ip_elevated": 15,
    # honeypot (W1 Ch7)
    "honeypot_filled": 100,
    # automation (W2 Ch1, Ch4)
    "no_telemetry": 40,
    "webdriver_flag": 60,
    "cdp_artifacts": 40,
    # fingerprint (W2 Ch2)
    "headless_gpu": 35,
    "fp_randomized": 15,
    "fp_inconsistent": 15,
    # behaviour (W2 Ch5)
    "no_pointer": 25,
    "mouse_too_straight": 15,
    "timing_too_regular": 15,
    "no_keystrokes": 10,
    # correlation
    "telemetry_replay": 60,
    "fp_reuse": 30,
    "tz_geo_mismatch": 10,
    "lang_mismatch": 25,
    # campaign and containment: rules, not points (see CAMPAIGN_ACTION)
    "campaign_cluster": 0,
    "asn_stepup": 0,
    # the model (defenses/model.py). Thresholds belong to the model version; these weights belong
    # to the policy, and a weight of 0 is the kill switch for a model that has gone wrong.
    "model_suspicious": 30,
    "model_bot": 60,
}

CHALLENGE_AT = 30
BLOCK_AT = 60

# The challenge type a score in the middle band is served (registered by demo_site/ext/risk.py).
DEFAULT_CHALLENGE = "pow"

# What a hot campaign cluster does to a login the score would otherwise allow. An emailed code
# costs a real user a minute and a credential stuffer everything. Off by default: the operator
# turns the campaign layer on (config.campaign) as a containment measure, with a TTL.
CAMPAIGN_ACTION = "step_up"

# Seconds a solved challenge stays valid (it is spent by the one login it unlocks).
CLEARANCE_TTL = 300

# Rate-limit buckets are not used in this chapter; the layers keep their own windows.
RATE_LIMITS = {}

FORCING = ("campaign_cluster", "asn_stepup")


def score(signals, weights=None):
    """Raw points: signals are Signals or signal names. Uncapped, unlike Decision.score."""
    weights = weights or WEIGHTS
    return sum(weights.get(getattr(s, "name", s), 0) for s in signals)


def explain(names, weights=None, challenge_at=None, block_at=None, campaign_action=None):
    """The ladder over signal names. Returns (action, points): "block", "challenge" or "allow".
    tools/sweep.py replays logged traffic with it."""
    challenge_at = CHALLENGE_AT if challenge_at is None else challenge_at
    block_at = BLOCK_AT if block_at is None else block_at
    campaign_action = campaign_action or CAMPAIGN_ACTION
    total = score(names, weights)
    if total >= block_at:
        return "block", total
    if any(n in FORCING for n in names):
        return ("block" if campaign_action == "block" else "challenge"), total
    if total >= challenge_at:
        return "challenge", total
    return "allow", total


def _request_state():
    """The request's operational state (defenses/ops.py), found through flask.g because the
    pipeline hands decide() no ctx. None outside a request."""
    try:
        from flask import g
        ctx = getattr(g, "ctx", None)
    except RuntimeError:
        return None, None
    return (ctx, ctx.attrs.get("ops")) if ctx is not None else (None, None)


def decide(total, signals, level):
    """pipeline.run() calls this with the checks' Signals. `total` is capped at 100, so score again
    from the signals' own points (which already carry the operator's weights)."""
    ctx, ops = _request_state()
    ops = ops or {}
    names = [s.name for s in signals]
    action, _ = explain(names, {s.name: s.points for s in signals}, ops.get("challenge_at"), ops.get("block_at"))
    if action == "block":
        action = "deceive"          # a block answers exactly like a wrong password (ext/risk.py)
    if ops.get("known_good") and action != "allow":
        ctx.note(would_be=action)
        return "monitor"
    return action
