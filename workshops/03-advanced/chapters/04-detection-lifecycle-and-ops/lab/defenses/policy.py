"""
Risk score and response ladder (inherited from W2 Ch8, Round 2+)

Every signal from every layer adds points to one score, and the score picks
a rung on the response ladder:

    score <  CHALLENGE_AT              allow
    CHALLENGE_AT <= score < BLOCK_AT   pow      proof-of-work challenge (ladder.py)
    score >= BLOCK_AT                  block
    hot campaign cluster (Round 4)     CAMPAIGN_ACTION, unless the score already blocks

Why a ladder instead of a yes/no:
- One weak signal (a VPN, a password manager) costs a real user nothing.
- Several weak signals together, which is what the Round 1 bot shows, add
  up to a block even though no layer is sure by itself.
- The middle band buys certainty with friction instead of with a block. A
  challenge is a *cost*, not a verdict: humans pay it in seconds, bots in
  CPU. It stops lazy bots and only slows determined ones (Round 2's attack).

Weights are a statement about how much you trust each signal, and about the
people each one hurts by mistake. Write them down next to their false
positives, and change them with data (tools/sweep.py), not with feelings.

W3 Ch4: the shipped weights below are the *deploy-time* policy. The
operator's overrides live in data/ops_config.json (defenses/config.py) and
win at request time, so a weight can go to zero (a kill switch) or up (a
burned signal's replacement) without a restart. `tools/configure.py` writes
them; `tools/sweep.py` replays last week's log against them first.
"""

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
    # TLS (W2 Ch5)
    "ja4_non_browser": 50,
    "ja4_ua_mismatch": 30,
    # velocity (W1 Ch2)
    "ip_burst": 30,
    "ip_elevated": 15,
    # honeypot (W1 Ch8)
    "honeypot_filled": 100,
    # automation (W2 Ch1-2)
    "no_telemetry": 40,
    "webdriver_flag": 60,
    "cdp_artifacts": 40,
    # fingerprint (W2 Ch4)
    "headless_gpu": 35,
    "fp_randomized": 15,
    "fp_inconsistent": 15,
    # behaviour (W2 Ch3)
    "no_pointer": 25,
    "mouse_too_straight": 15,
    "timing_too_regular": 15,
    "no_keystrokes": 10,
    # correlation (Round 3)
    "telemetry_replay": 60,
    "fp_reuse": 30,
    "tz_geo_mismatch": 10,
    "lang_mismatch": 25,
    # campaign (W2 Ch8 Round 4): a rule, not points (see CAMPAIGN_ACTION)
    "campaign_cluster": 0,
    # the model (W2 Ch7, now a sensor: defenses/model.py). Thresholds belong
    # to the model version; these weights belong to the policy.
    "model_suspicious": 30,
    "model_bot": 60,
}

CHALLENGE_AT = 30
BLOCK_AT = 60

# What a hot campaign cluster does to a login the score would otherwise
# allow (W2 Ch8 settled on step_up: it costs real users a minute and a
# credential stuffer everything). Off by default here; Round 4 turns the
# campaign layer on as a containment measure, with a TTL.
CAMPAIGN_ACTION = "step_up"


def score(signals, weights=None):
    weights = weights or WEIGHTS
    return sum(weights.get(s, 0) for s in signals)


def decide(signals, weights=None, challenge_at=None, block_at=None, campaign_action=None):
    """Map a list of signals to (action, score). The optional arguments let
    tools/sweep.py replay logged traffic against a different policy."""
    challenge_at = CHALLENGE_AT if challenge_at is None else challenge_at
    block_at = BLOCK_AT if block_at is None else block_at
    campaign_action = campaign_action or CAMPAIGN_ACTION
    total = score(signals, weights)
    if total >= block_at:
        return "block", total
    if "campaign_cluster" in signals:
        return campaign_action, total
    if total >= challenge_at:
        return "pow", total
    return "allow", total
