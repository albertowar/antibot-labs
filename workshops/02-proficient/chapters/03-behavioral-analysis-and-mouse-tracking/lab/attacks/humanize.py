"""
Chapter 3: a ghost-cursor-style humanizer for Playwright (Section 3.5).

Modelled on the recipe popularised by ghost-cursor (Xetera, npm, 2019-2026)
and its many ports, re-implemented here in ~60 lines so you can read it:

    - cubic Bezier path with random control points ("spread")
    - number of steps from Fitts's law: longer moves and smaller targets
      get more points
    - overshoot long moves, then come back (a fake "correction")
    - click a random point inside the element, not its centre
    - Gaussian key hold and key gap times

`ease=True` adds smoothstep easing so the cursor starts and stops slowly,
as several humanizers do. Both variants are used in Round 3.

What it gets wrong, on purpose, because the libraries do too: without
easing, points are uniform in the curve parameter t, so the cursor is still
moving fast when it reaches the target; with easing, acceleration and
deceleration take exactly the same time. Real hands do neither (l3_motor.py).
"""

import math
import random

from _common import sleep_ms


def _bezier(p0, p1, p2, p3, t):
    u = 1 - t
    return (u ** 3 * p0[0] + 3 * u * u * t * p1[0] + 3 * u * t * t * p2[0] + t ** 3 * p3[0],
            u ** 3 * p0[1] + 3 * u * u * t * p1[1] + 3 * u * t * t * p2[1] + t ** 3 * p3[1])


def bezier_path(start, end, target_width=100, spread=None, ease=False, rng=random):
    dx, dy = end[0] - start[0], end[1] - start[1]
    dist = math.hypot(dx, dy) or 1
    spread = spread if spread is not None else min(200, max(2, dist * 0.3))
    nx, ny = -dy / dist, dx / dist                       # unit normal
    a, b = rng.uniform(0.2, 0.45), rng.uniform(0.55, 0.8)
    p1 = (start[0] + dx * a + nx * rng.uniform(-spread, spread),
          start[1] + dy * a + ny * rng.uniform(-spread, spread))
    p2 = (start[0] + dx * b + nx * rng.uniform(-spread, spread),
          start[1] + dy * b + ny * rng.uniform(-spread, spread))
    fitts = math.log2(dist / max(target_width, 1) + 1)
    steps = max(12, min(60, int((fitts + 2) * 6 + rng.uniform(0, 6))))
    points = []
    for i in range(1, steps + 1):
        t = i / steps
        if ease:
            t = t * t * (3 - 2 * t)                      # smoothstep
        x, y = _bezier(start, p1, p2, end, t)
        points.append((x + rng.gauss(0, 0.4), y + rng.gauss(0, 0.4)))
    points[-1] = end
    return points


class Cursor:
    def __init__(self, page, ease=False, rng=random):
        self.page, self.ease, self.rng = page, ease, rng
        self.pos = (0.0, 0.0)          # where Playwright's mouse starts, like ghost-cursor's default

    def move_to(self, x, y, width=100):
        dist = math.hypot(x - self.pos[0], y - self.pos[1])
        legs = [((x, y), width)]
        if dist > 500:                 # ghost-cursor's overshootThreshold
            angle = self.rng.uniform(0, 2 * math.pi)
            r = self.rng.uniform(40, 120)
            legs = [((x + r * math.cos(angle), y + r * math.sin(angle)), width), ((x, y), width)]
        for end, w in legs:
            for px, py in bezier_path(self.pos, end, w, ease=self.ease, rng=self.rng):
                self.page.mouse.move(px, py)       # each call is one pointermove (~1 frame)
            self.pos = end

    def click(self, selector):
        b = self.page.locator(selector).bounding_box()
        x = b["x"] + b["width"] * self.rng.uniform(0.15, 0.85)
        y = b["y"] + b["height"] * self.rng.uniform(0.2, 0.8)
        self.move_to(x, y, b["width"])
        sleep_ms(self.rng.uniform(60, 160))
        self.page.mouse.down()
        sleep_ms(self.rng.uniform(60, 120))
        self.page.mouse.up()


def human_type(page, text, rng=random):
    """Gaussian hold (90 +/- 20 ms) and gap (110 +/- 35 ms): plausible means, wrong shape."""
    for ch in text:
        page.keyboard.down(ch)
        sleep_ms(max(30, rng.gauss(90, 20)))
        page.keyboard.up(ch)
        sleep_ms(max(20, rng.gauss(110, 35)))
