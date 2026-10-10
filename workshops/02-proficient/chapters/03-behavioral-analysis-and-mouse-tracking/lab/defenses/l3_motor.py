"""
Chapter 3, Layer 3: motor-control realism (Section 3.5, Round 3).

The bot now draws curved Bezier paths with random control points, overshoots
long moves, clicks a random point in the button and types with Gaussian
delays: the ghost-cursor recipe. Each point looks fine; the *physics* doesn't.

Human aimed movements (Fitts 1954; Plamondon's Kinematic Theory, 1995) are
built from lognormal velocity strokes: speed rises fast, falls slowly, and
the hand arrives at the target almost stopped, often after a small
correction. A Bezier curve walked at uniform t steps arrives at full speed.

    rule                        points  why it fires
    no deceleration at target   45      median end_ratio > 0.35 over the session's approaches
    weak deceleration           25      median end_ratio > 0.20
    Gaussian typing rhythm      15      no rollover and |skew| < 0.5 over >= 15 intervals

    end_ratio = mean speed over the last 15% of an approach / its peak speed
                (humans: median ~0.06; uniform-t Bezier: ~0.6; eased Bezier: ~0.25)

Typing: human inter-key intervals are right-skewed (most keys fast, a long
tail of pauses) and fast typists press the next key before releasing the
last ("rollover"). random.gauss() gives neither.

False positives you should expect:
    - People who click "on the fly" without slowing down on large buttons.
      The weak tier alone (25) stays below the challenge threshold on purpose.
    - Slow, deliberate typists (hunt-and-peck) never roll keys over. That alone
      is 15 points: logged, never a challenge.
    - Tremor and motor impairments make paths *messier*, not smoother. None of
      these rules punishes noise; rules that do ("too erratic") hurt them.

What does NOT work well enough to score (measure it yourself, TODO below):
the asymmetry of the speed profile (features.py "asymmetry"). Real and
synthetic humans are asymmetric on average, but per session the spread is
wide: a rule that catches eased Bezier curves challenges ~10% of humans.

This is the most expensive layer to keep honest: it is tuned against a
model of human movement, and a better attacker model (lognormal strokes,
diffusion models trained on real traces) closes the gap. Section 3.8.
"""

STRONG_END, WEAK_END = 0.35, 0.20
MIN_IKI = 15


def _median(values):
    values = sorted(values)
    n = len(values)
    if not n:
        return None
    return values[n // 2] if n % 2 else (values[n // 2 - 1] + values[n // 2]) / 2


def score_motor(features):
    reasons = []
    shaped = [m for m in features["approaches"] if m.get("end_ratio") is not None]

    end = _median([m["end_ratio"] for m in shaped])
    if end is not None and end > STRONG_END:
        reasons.append((45, f"No deceleration at the target: median end/peak speed {end:.2f} "
                            f"over {len(shaped)} approaches"))
    elif end is not None and end > WEAK_END:
        reasons.append((25, f"Weak deceleration at the target: median end/peak speed {end:.2f}"))

    k = features["keys"]
    if (k["n_iki"] >= MIN_IKI and k["rollover_ratio"] == 0
            and k["iki_skew"] is not None and abs(k["iki_skew"]) < 0.5):
        reasons.append((15, f"Gaussian typing rhythm: no rollover, inter-key skew {k['iki_skew']}"))

    # TODO (Round 3, optional): add a "symmetric speed profile" rule using the
    # median of m["asymmetry"] (deceleration time / acceleration time; an eased
    # curve is ~1.0). Pick a threshold, then run `python tools/humans.py` and
    # count how many synthetic humans it challenges. Would you ship it?
    return reasons


if __name__ == "__main__":
    import json
    import sys
    from features import extract
    trace = json.load(open(sys.argv[1]))
    for points, reason in score_motor(extract(trace["telemetry"], trace["layout"])):
        print(f"{points:>3}  {reason}")
