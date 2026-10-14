"""
Policy: how the layers' signals become one answer. (Round 2's file; Round 4 tunes CAMPAIGN_ACTION.)

The layers (sensors.py, correlation.py, campaign.py) only report signals. This file decides what
to do with them, and the answer changes with DEFENSE_LEVEL:

    level 0   shadow mode   every layer runs and logs; nothing is enforced          allow
    level 1   veto chain    any one layer over its own line blocks (veto.py)        allow | block
    level 2   risk score    one score; the response ladder below                    allow | pow | block
    level 3   + correlation (correlation.py), and a block looks like a typo         ... | deceive
    level 4   + campaign    a hot cluster is forced up the ladder (campaign.py)     ... | step_up

The risk score (levels 2+). Every signal adds its WEIGHT:

    score <  CHALLENGE_AT              allow
    CHALLENGE_AT <= score < BLOCK_AT   challenge   a proof of work (DEFAULT_CHALLENGE)
    score >= BLOCK_AT                  block       403 at level 2; "Wrong email or password" from level 3
    hot campaign cluster (level 4)     CAMPAIGN_ACTION, unless the score already blocks

Why a ladder instead of a yes/no:
- One weak signal (a VPN, a password manager) costs a real user nothing.
- Several weak signals together, which is what the Round 1 bot shows, add up to a block even
  though no layer is sure by itself.
- The middle band buys certainty with friction instead of with a block. A challenge is a *cost*,
  not a verdict: humans pay it in seconds, bots in CPU. It stops lazy bots and only slows
  determined ones (Round 2's attack).

Weights are a statement about how much you trust each signal, and about the people each one hurts
by mistake. Write them down next to their false positives, and change them with data
(tools/sweep.py), not with feelings.
"""

from . import veto

# TODO (Round 2): read every weight next to the false-positive notes in sensor_*.py. Which persona
# does each one hurt? Try changing one weight, run `python tools/sweep.py`, and see who moves.
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
    # campaign (Round 4): a rule, not points (see CAMPAIGN_ACTION)
    "campaign_cluster": 0,
}

CHALLENGE_AT = 30
BLOCK_AT = 60

# The challenge type a score in the middle band is served (registered by demo_site/ext/risk.py).
DEFAULT_CHALLENGE = "pow"

# TODO (Round 4): what should a hot campaign cluster do to a login that the score would otherwise
# allow? "pow" is cheap for the bot, "block" hits every real user in the cluster, and "step_up"
# (an emailed code) costs real users a minute and the bot everything. Try all three with the sweep.
CAMPAIGN_ACTION = "step_up"

# Seconds a solved challenge stays valid (it is spent by the one login it unlocks).
CLEARANCE_TTL = 300

# Rate-limit buckets are not used in this chapter; the layers keep their own windows.
RATE_LIMITS = {}


def score(signals, weights=None):
    """Raw points: signals are Signals or signal names. Uncapped, unlike Decision.score."""
    weights = weights or WEIGHTS
    return sum(weights.get(getattr(s, "name", s), 0) for s in signals)


def block_action(level):
    """From level 3 a block is deceptive: the client is told it mistyped (ext/risk.py makes it so)."""
    return "deceive" if level >= 3 else "block"


def explain(names, weights=None, challenge_at=None, block_at=None, campaign_action=None, level=4):
    """The level >= 2 ladder over signal names. Returns (action, points); tools/sweep.py replays with it."""
    challenge_at = CHALLENGE_AT if challenge_at is None else challenge_at
    block_at = BLOCK_AT if block_at is None else block_at
    campaign_action = campaign_action or CAMPAIGN_ACTION
    total = score(names, weights)
    if total >= block_at:
        return block_action(level), total
    if "campaign_cluster" in names:
        return ("challenge" if campaign_action != "block" else block_action(level)), total
    if total >= challenge_at:
        return "challenge", total
    return "allow", total


def decide(total, signals, level):
    """pipeline.run() calls this with the checks' Signals. `total` is capped at 100, so score again."""
    if level <= 0:
        return "allow"                                  # shadow mode: observe, log, enforce nothing
    if level == 1:
        return "block" if veto.blocking_layer(signals) else "allow"
    action, _ = explain([s.name for s in signals], level=level)
    return action
