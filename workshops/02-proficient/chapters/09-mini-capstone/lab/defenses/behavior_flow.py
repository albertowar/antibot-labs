"""
Chapter 9 — L2 behavior and flow (W2 Ch3), enabled at DEFENSE_LEVEL >= 2

A native stealth browser such as Camoufox can make every fingerprint
attribute coherent. What it does by default is still *robotic*: it navigates
straight to the product and clicks the button the instant it appears. This
layer looks at how the session got to the click.

    Untrusted (synthetic) DOM events               +60   dispatchEvent / element.click() from JS
    Buy click with no pointer path before it       +45   automation "teleports" the cursor
    Perfectly straight, constant-speed path        +35   linear interpolation, no human jitter
    Less than MIN_DWELL_MS on the product page     +30   measured by the server, not the client
    Buy with no product-page view in this session  +40   direct API call

The dwell time comes from the server's own flow log (when it served the
product page), not from client telemetry, so it can't be replayed or edited.

Where it fails:
  - Keyboard and screen-reader users never move a mouse. They Tab to the
    button and press Enter, and the click arrives with detail == 0.
  - Touch users tap. There are no mousemove events at all.
  - Camoufox's humanize=True and libraries such as ghost-cursor generate
    curved, accelerating paths that pass shape checks.
  - Every exemption you add for accessibility is a door the next bot will
    try (Round 3).
"""

import math

MIN_DWELL_MS = 1000
MIN_MOVES_BEFORE_CLICK = 3


def _buy_click(events):
    clicks = [c for c in events.get("clicks", []) if len(c) >= 5 and c[4] == "buy"]
    return clicks[-1] if clicks else None


def path_shape(moves):
    """Straightness (chord / path length, 1.0 = ruler-straight) and speed variation."""
    if len(moves) < 5:
        return None, None
    length, speeds = 0.0, []
    for (t0, x0, y0), (t1, x1, y1) in zip(moves, moves[1:]):
        d = math.hypot(x1 - x0, y1 - y0)
        length += d
        if t1 > t0:
            speeds.append(d / (t1 - t0))
    chord = math.hypot(moves[-1][1] - moves[0][1], moves[-1][2] - moves[0][2])
    straightness = chord / length if length else 1.0
    mean = sum(speeds) / len(speeds) if speeds else 0
    cv = (math.sqrt(sum((s - mean) ** 2 for s in speeds) / len(speeds)) / mean) if mean else 0
    return straightness, cv


def score_behavior(sess):
    events, flow, page = sess["events"], sess["flow"], sess["page"]
    if events is None:
        return 0, []  # missing telemetry is an L0 signal
    points, reasons = 0, []

    if events.get("untrusted", 0) > 0:
        points += 60
        reasons.append(f"{events['untrusted']} untrusted (script-generated) events")

    click = _buy_click(events)
    moves = events.get("moves", [])
    if click is not None:
        before = [m for m in moves if m[0] <= click[0]]
        # TODO (Round 2): this flags keyboard and touch users too (see the
        # "screen-reader" and "safari-ios" personas in the checkpoint).
        # Don't add points when the click was keyboard-activated (click[3] == 0,
        # i.e. detail 0, after Tab/Enter keydowns) or when the page saw touches.
        if len(before) < MIN_MOVES_BEFORE_CLICK:
            points += 45
            reasons.append(f"Buy click with {len(before)} pointer moves before it")
        straightness, cv = path_shape(before[-30:])
        if straightness is not None and straightness > 0.99 and cv < 0.15:
            points += 35
            reasons.append(f"Ruler-straight, constant-speed pointer path (straightness {straightness:.3f}, "
                           f"speed CV {cv:.2f})")

    views = [t for t, path in flow if path == page]
    if not views:
        points += 40
        reasons.append(f"Buy without a view of {page} in this session")
    else:
        dwell = sess["now_ms"] - views[-1]
        if dwell < MIN_DWELL_MS:
            points += 30
            reasons.append(f"Bought {dwell} ms after the product page was served (min {MIN_DWELL_MS})")
    return points, reasons


if __name__ == '__main__':
    sess = {"page": "/drop/lab-runner-9", "now_ms": 10_400, "flow": [[10_000, "/drop/lab-runner-9"]],
            "events": {"moves": [[300, 640, 360]], "clicks": [[310, 640, 360, 1, "buy"]], "keys": [],
                       "touches": [], "untrusted": 0}}
    print(score_behavior(sess))
