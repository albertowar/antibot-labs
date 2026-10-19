"""
Chapter 5, Layer 2: kinematics & keystroke dynamics (Section 5.4, Round 2).

The bot now moves the mouse and presses real keys. Does the movement look
like a hand, and the typing like fingers?

    rule                        points  why it fires
    ruler-straight approach     35      straightness > 0.995 AND equal-sized steps (step CV < 0.15)
    zero-dwell typing           35      keys held < 15 ms on average (press = down+up at once)
    no gap between keys         35      > 70% of keys pressed within 8 ms of the previous release
    metronome typing            35      dwell CV < 0.12 and inter-key CV < 0.12

    (the three typing rules need >= 8 keys and only the first that matches counts)

Why both conditions on the path: people make short, fast, nearly straight
flicks too. What they don't make is a straight line *at constant speed*:
a hand accelerates and decelerates, so its step sizes vary a lot.

Exempt, on purpose:
    - Touch and keyboard-only sessions have no mouse approaches, so the path
      rule simply has nothing to look at. No mouse is not evidence.
    - Virtual keyboards (Android reports key "Unidentified") fire keydown and
      keyup together: dwell ~0 ms for every real phone user. Those keys are
      counted separately (ime_keys) and never feed the dwell rules.

False positives you should expect: very fast, very regular typists rarely
get below CV 0.12 on both measures; stenography and some assistive typing
tools can. Log the scores and look before you lower thresholds.

Enabled for POST /drop/<sku> (action:drop_buy) when DEFENSE_LEVEL >= 2.
"""

from . import behavior
from .pipeline import Check


STRAIGHT = 0.995
STEP_CV = 0.15
REGULAR_CV = 0.12
MIN_KEYS = 8
ZERO_DWELL_MS = 15
INSTANT_FLIGHT = 0.7


def score_kinematics(features):
    if features is None:
        return []
    reasons = []
    linear = [m for m in features["approaches"]
              if m["straightness"] > STRAIGHT and m["step_cv"] < STEP_CV]
    if linear:
        m = linear[0]
        reasons.append((35, "ruler_path", f"Ruler-straight approach at constant speed: {len(linear)} of "
                            f"{len(features['approaches'])} (straightness {m['straightness']}, "
                            f"step CV {m['step_cv']})"))

    k = features["keys"]
    if k["n_dwell"] >= MIN_KEYS:
        if k["dwell_mean"] is not None and k["dwell_mean"] < ZERO_DWELL_MS:
            reasons.append((35, "zero_dwell", f"Keys held {k['dwell_mean']:.1f} ms on average (zero-dwell typing)"))
        elif k["instant_flight_ratio"] is not None and k["instant_flight_ratio"] > INSTANT_FLIGHT:
            reasons.append((35, "instant_flight", f"No gap between keys: {k['instant_flight_ratio']:.0%} pressed within "
                                "8 ms of the previous release"))
        elif (k["dwell_cv"] is not None and k["iki_cv"] is not None
              and k["dwell_cv"] < REGULAR_CV and k["iki_cv"] < REGULAR_CV):
            reasons.append((35, "metronome", f"Metronome typing: dwell CV {k['dwell_cv']}, inter-key CV {k['iki_cv']}"))
    return reasons


CHECK = Check("behavior_l2", lambda ctx: behavior.signals("l2", score_kinematics(behavior.features(ctx))),
              phases=("action:drop_buy",))
