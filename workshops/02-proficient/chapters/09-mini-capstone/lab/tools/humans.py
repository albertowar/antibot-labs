"""
Chapter 9 — Synthetic human input for the legitimate-traffic simulator

Generates the same event structure collector.js records: moves [t, x, y],
clicks [t, x, y, detail, target], keys [t, kind], touches [t, x, y].

Mouse paths follow the minimum-jerk model of human reaching (Flash & Hogan,
1985): a bell-shaped speed profile, a slightly curved path, small tremor,
and a corrective sub-movement after an overshoot. That is the kind of
motion humanizers try to imitate, which is why shape checks alone don't
hold up (Round 3).

Honest caveat: these are models of people, not people. A defense tuned
only on simulated humans learns the simulator. Capture your own browser at
/lab/capture and add it to tools/profiles/ so at least one real human is in
every checkpoint.
"""

import math

BUY_BUTTON = (72, 164)  # approximate centre of #buy in the demo store layout
SAMPLE_MS = 16


def _reach(rng, t0, start, end, duration_ms):
    """One minimum-jerk reach with curvature and tremor. Returns [[t, x, y], ...]."""
    (x0, y0), (x1, y1) = start, end
    dx, dy = x1 - x0, y1 - y0
    dist = math.hypot(dx, dy) or 1.0
    nx, ny = -dy / dist, dx / dist
    bow = rng.gauss(0, 0.08) * dist
    out, t = [], 0.0
    while t < duration_ms:
        tau = t / duration_ms
        s = 10 * tau ** 3 - 15 * tau ** 4 + 6 * tau ** 5
        off = bow * math.sin(math.pi * tau)
        out.append([int(t0 + t), round(x0 + dx * s + nx * off + rng.gauss(0, 0.6)),
                    round(y0 + dy * s + ny * off + rng.gauss(0, 0.6))])
        t += SAMPLE_MS + rng.uniform(-3, 4)
    return out


def mouse_events(rng, dwell_ms, fast=False):
    """Wander, then reach for the Buy button with an overshoot and a correction."""
    moves, t = [], rng.uniform(120, 400)
    pos = (rng.uniform(250, 900), rng.uniform(80, 600))
    if not fast:
        for _ in range(rng.randint(1, 3)):
            nxt = (rng.uniform(40, 1100), rng.uniform(40, 700))
            dur = rng.uniform(350, 900)
            moves += _reach(rng, t, pos, nxt, dur)
            t += dur + rng.uniform(150, 700)
            pos = nxt
    target = (BUY_BUTTON[0] + rng.uniform(-25, 25), BUY_BUTTON[1] + rng.uniform(-8, 8))
    overshoot = (target[0] + rng.uniform(4, 14), target[1] + rng.uniform(-6, 6))
    reach_ms = rng.uniform(280, 420) if fast else rng.uniform(450, 900)
    start_reach = max(t, dwell_ms - reach_ms - rng.uniform(250, 500))
    moves += _reach(rng, start_reach, pos, overshoot, reach_ms)
    correction_t = start_reach + reach_ms + rng.uniform(20, 60)
    moves += _reach(rng, correction_t, overshoot, target, rng.uniform(120, 220))
    click_t = int(moves[-1][0] + rng.uniform(60, 180))
    return {"moves": moves[-400:], "clicks": [[click_t, round(target[0]), round(target[1]), 1, "buy"]],
            "keys": [], "touches": [], "scrolls": rng.randint(0, 3), "untrusted": 0}


def keyboard_events(rng, dwell_ms):
    """Screen-reader / keyboard-only user: Tab through the page, Enter on the button."""
    keys, t = [], rng.uniform(300, 700)
    for _ in range(rng.randint(5, 10)):
        keys.append([int(t), "Tab"])
        t += rng.uniform(220, 650)
    t = max(t, dwell_ms - rng.uniform(100, 250))
    keys.append([int(t), "Enter"])
    return {"moves": [], "clicks": [[int(t + 3), 0, 0, 0, "buy"]], "keys": keys, "touches": [],
            "scrolls": 0, "untrusted": 0}


def touch_events(rng, dwell_ms):
    """Phone user: a few scroll touches, then a tap. iOS fires one compatibility mousemove per tap."""
    touches, t = [], rng.uniform(300, 800)
    for _ in range(rng.randint(1, 3)):
        touches.append([int(t), round(rng.uniform(40, 350)), round(rng.uniform(200, 700))])
        t += rng.uniform(400, 1100)
    tap_t = max(t, dwell_ms - rng.uniform(150, 300))
    x, y = BUY_BUTTON[0] + rng.uniform(-20, 20), BUY_BUTTON[1] + rng.uniform(-6, 6)
    touches.append([int(tap_t), round(x), round(y)])
    return {"moves": [[int(tap_t + 30), round(x), round(y)]],
            "clicks": [[int(tap_t + 40), round(x), round(y), 1, "buy"]],
            "keys": [], "touches": touches, "scrolls": rng.randint(2, 6), "untrusted": 0}


def typing_events(rng, n_chars):
    """Keystroke timing for a login form (no key values, as in collector.js)."""
    keys, t = [], rng.uniform(400, 1200)
    for _ in range(n_chars):
        keys.append([int(t), "key"])
        t += max(40, rng.gauss(165, 55))
    keys.append([int(t + rng.uniform(200, 600)), "Enter"])
    return {"moves": [], "clicks": [], "keys": keys, "touches": [], "scrolls": 0, "untrusted": 0}


def events_for(behavior, rng, dwell_ms):
    if behavior == "keyboard":
        return keyboard_events(rng, dwell_ms)
    if behavior == "touch":
        return touch_events(rng, dwell_ms)
    return mouse_events(rng, dwell_ms, fast=(behavior == "fast"))


if __name__ == '__main__':
    import random
    ev = mouse_events(random.Random(1), 3000)
    print(f"{len(ev['moves'])} moves, click at {ev['clicks'][0][:3]}")
