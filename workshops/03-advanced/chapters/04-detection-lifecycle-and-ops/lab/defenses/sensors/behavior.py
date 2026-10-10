"""
Layer: behaviour (stand-in for W2 Ch3)

Looks at the short mouse/keyboard trace that came with the login:
- no pointer events at all
- a pointer path that is a ruler-straight line
- event timing with almost no jitter (a timer, not a hand)
- credentials that arrived without a single keystroke

False positives, and they are the important part of this file:
- keyboard-only and screen-reader users produce no pointer events
- password managers and paste fill the form with no keystrokes
- touch devices produce a few taps, not a path, so path checks skip short traces
Behaviour is a strong layer *in combination* and a cruel one alone.
"""

LAYER = "behavior"
SIGNALS = {
    "no_pointer": "no pointer or touch events before submit",
    "mouse_too_straight": "pointer path is a straight line",
    "timing_too_regular": "pointer events arrive like a timer",
    "no_keystrokes": "form filled without keystrokes",
}

MIN_PATH_EVENTS = 10


def sense(ctx):
    t = ctx.telemetry
    if t is None:
        return []
    found = []
    if t["pointer_events"] == 0:
        found.append("no_pointer")
    elif t["pointer_events"] >= MIN_PATH_EVENTS:
        if t["straightness"] > 0.98:
            found.append("mouse_too_straight")
        if t["interval_std_ms"] is not None and t["interval_std_ms"] < 2.0:
            found.append("timing_too_regular")
    if t["keystrokes"] == 0:
        found.append("no_keystrokes")
    return found
