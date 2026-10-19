"""
W4 Ch10 Capstone — Synthetic human input for the legitimate-traffic simulator

Generates the event structure collector.js records:
    moves [t, x, y]   clicks [t, x, y, detail, target]   keys [t, kind]   touches [t, x, y]
    inputs [t, field, chars, keydowns_since_last]   scroll_events [t, programmatic]   overlays []

Mouse paths follow the minimum-jerk model of human reaching (Flash & Hogan,
1985), as in W2 Ch9. New here are the input styles that matter for an
agent-aware defense:

    keyboard   screen-reader user: Tab … Enter, click detail 0, no pointer path
    at         voice control / switch access: activation through the accessibility
               tree, click detail 0, no keys, no pointer path
    autofill   a password manager fills both login fields with zero keystrokes
    rpa        a desktop macro: teleport pointer click (detail 1) and instant fills
    agent      what a DOM-driven agent's hands look like (teleport click, fill())

Honest caveat: these are models of people, not people. A defense tuned only
on simulated humans learns the simulator.
"""

import math

TARGETS = {"place-order": (90, 260), "add-to-cart": (80, 220), "login-submit": (60, 300),
           "register-submit": (60, 360), "confirm-submit": (90, 420)}
SAMPLE_MS = 16


def _reach(rng, t0, start, end, duration_ms):
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


def _empty():
    return {"moves": [], "clicks": [], "keys": [], "touches": [], "inputs": [], "scroll_events": [],
            "overlays": [], "scrolls": 0, "untrusted": 0}


def mouse_events(rng, dwell_ms, target="place-order", fast=False):
    """Wander, then reach for the button with an overshoot and a correction."""
    ev = _empty()
    tx, ty = TARGETS.get(target, (90, 260))
    t = rng.uniform(120, 400)
    pos = (rng.uniform(250, 900), rng.uniform(80, 600))
    if not fast:
        for _ in range(rng.randint(1, 3)):
            nxt = (rng.uniform(40, 1100), rng.uniform(40, 700))
            dur = rng.uniform(350, 900)
            ev["moves"] += _reach(rng, t, pos, nxt, dur)
            t += dur + rng.uniform(150, 700)
            pos = nxt
        if rng.random() < 0.5:
            ev["scroll_events"].append([int(t), 0])
            ev["scrolls"] = 1
    end = (tx + rng.uniform(-25, 25), ty + rng.uniform(-8, 8))
    overshoot = (end[0] + rng.uniform(4, 14), end[1] + rng.uniform(-6, 6))
    reach_ms = rng.uniform(280, 420) if fast else rng.uniform(450, 900)
    start_reach = max(t, dwell_ms - reach_ms - rng.uniform(250, 500))
    ev["moves"] += _reach(rng, start_reach, pos, overshoot, reach_ms)
    ev["moves"] += _reach(rng, start_reach + reach_ms + rng.uniform(20, 60), overshoot, end, rng.uniform(120, 220))
    ev["moves"] = ev["moves"][-400:]
    click_t = int(ev["moves"][-1][0] + rng.uniform(60, 180))
    ev["clicks"].append([click_t, round(end[0]), round(end[1]), 1, target])
    return ev


def keyboard_events(rng, dwell_ms, target="place-order"):
    """Screen-reader / keyboard-only user: Tab through the page, Enter on the button."""
    ev, t = _empty(), rng.uniform(300, 700)
    for _ in range(rng.randint(4, 9)):
        ev["keys"].append([int(t), "Tab"])
        t += rng.uniform(220, 650)
    t = max(t, dwell_ms - rng.uniform(100, 250))
    ev["keys"].append([int(t), "Enter"])
    ev["clicks"].append([int(t + 3), 0, 0, 0, target])
    return ev


def at_events(rng, dwell_ms, target="place-order"):
    """Voice control / switch access: the control is activated through the accessibility tree."""
    ev = _empty()
    t = max(rng.uniform(900, 1800), dwell_ms - rng.uniform(100, 300))
    ev["clicks"].append([int(t), 0, 0, 0, target])
    return ev


def touch_events(rng, dwell_ms, target="place-order"):
    ev, t = _empty(), rng.uniform(300, 800)
    tx, ty = TARGETS.get(target, (90, 260))
    for _ in range(rng.randint(1, 3)):
        ev["touches"].append([int(t), round(rng.uniform(40, 350)), round(rng.uniform(200, 700))])
        ev["scroll_events"].append([int(t + 30), 0])
        t += rng.uniform(400, 1100)
    tap_t = max(t, dwell_ms - rng.uniform(150, 300))
    x, y = tx + rng.uniform(-20, 20), ty + rng.uniform(-6, 6)
    ev["touches"].append([int(tap_t), round(x), round(y)])
    ev["moves"].append([int(tap_t + 30), round(x), round(y)])
    ev["clicks"].append([int(tap_t + 40), round(x), round(y), 1, target])
    ev["scrolls"] = len(ev["scroll_events"])
    return ev


def rpa_events(rng, dwell_ms, target="place-order"):
    """A desktop macro: the cursor jumps to the control and clicks it. No path, detail 1."""
    ev = _empty()
    tx, ty = TARGETS.get(target, (90, 260))
    t = max(rng.uniform(300, 600), dwell_ms - 50)
    ev["moves"].append([int(t) - 1, tx, ty])
    ev["clicks"].append([int(t), tx, ty, 1, target])
    return ev


def typing_events(rng, fields, style="typing"):
    """Login/register form input. fields: [(name, n_chars)]. style: typing | autofill | rpa."""
    ev, t = _empty(), rng.uniform(400, 1200)
    submit = "register-submit" if any(n == "address" for n, _ in fields) else "login-submit"
    for name, n in fields:
        if style == "typing":
            ev["clicks"].append([int(t), 60, 120, 1, name])
            t += rng.uniform(150, 400)
            for _ in range(n):
                ev["keys"].append([int(t), "key"])
                t += max(40, rng.gauss(165, 55))
            ev["inputs"].append([int(t), name, n, n])
            t += rng.uniform(200, 700)
        else:  # autofill and rpa: the value appears with no keystrokes
            ev["inputs"].append([int(t), name, n, 0])
            t += rng.uniform(30, 120) if style == "rpa" else rng.uniform(80, 250)
    if style == "typing":
        ev["keys"].append([int(t + rng.uniform(200, 600)), "Enter"])
        ev["clicks"].append([int(t + rng.uniform(210, 620)), 0, 0, 0, submit])
    elif style == "autofill":
        ev2 = mouse_events(rng, t + rng.uniform(700, 1500), target=submit)
        ev["moves"], ev["clicks"] = ev2["moves"], ev["clicks"] + ev2["clicks"]
    else:
        ev["moves"].append([int(t + 90), 60, 300])
        ev["clicks"].append([int(t + 100), 60, 300, 1, submit])
    return ev


def agent_events(rng, dwell_ms, target="place-order", fields=()):
    """What a DOM-driven agent's telemetry looks like: fill() and one teleport click."""
    ev = _empty()
    t = rng.uniform(600, 900)
    for name, n in fields:
        ev["inputs"].append([int(t), name, n, 0])
        t += rng.uniform(20, 60)
    t = max(t, dwell_ms - 20)
    tx, ty = TARGETS.get(target, (90, 260))
    ev["moves"].append([int(t) - 1, tx, ty])
    ev["clicks"].append([int(t), tx, ty, 1, target])
    return ev


def events_for(behavior, rng, dwell_ms, target="place-order", a11y=False):
    """a11y=True marks the session as driven through the accessibility API (what
    collector.js reports as events.a11y_api): screen readers, switch access, and
    assistive agents. It is a *signal*, never a verdict (W4 Ch8 §8.2.3)."""
    if behavior == "keyboard":
        ev = keyboard_events(rng, dwell_ms, target)
    elif behavior == "at":
        ev = at_events(rng, dwell_ms, target)
    elif behavior == "touch":
        ev = touch_events(rng, dwell_ms, target)
    elif behavior == "rpa":
        ev = rpa_events(rng, dwell_ms, target)
    elif behavior in ("agent-user", "agent"):
        ev = agent_events(rng, dwell_ms, target)
    else:
        ev = mouse_events(rng, dwell_ms, target, fast=(behavior == "fast"))
    if a11y or behavior in ("keyboard", "at"):
        ev["a11y_api"] = True
    return ev


def login_style(behavior):
    return {"autofill": "autofill", "rpa": "rpa", "agent-user": "rpa", "agent": "rpa"}.get(behavior, "typing")


if __name__ == '__main__':
    import random
    ev = mouse_events(random.Random(1), 3000)
    print(f"{len(ev['moves'])} moves, click at {ev['clicks'][0][:3]}")
    print(typing_events(random.Random(2), [("email", 20), ("password", 12)], "autofill")["inputs"])
