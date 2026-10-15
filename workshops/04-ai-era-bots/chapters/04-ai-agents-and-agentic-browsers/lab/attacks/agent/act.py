"""
The agent's "hands": perform one action in the browser.

    Executor          the stock way, how a DOM-driven agent acts: resolve the
                      element and click()/fill() it. No cursor path, no keystrokes.
                      This is what leaves the Round 2 tells.
    HumanizedExecutor the Round 2 evasion: move a Bezier cursor to the element and
                      type character by character, reusing the W2 Ch3 recipe
                      (ghost-cursor-style). Plausible means, still not a real hand,
                      but enough to clear the shape checks.

Both expose click(selector)/fill(selector, text)/goto(path)/flush(). The loop doesn't know which it
has, so the only thing that changes between Round 1 and Round 2 is this object.
"""

import math
import random
import time


class Executor:
    """Stock agent actions: resolve and act. Teleport click, instant fill."""

    def __init__(self, page, base, rng=None, think=(0.5, 0.7)):
        self.page, self.base, self.rng = page, base, rng or random.Random()
        self.think = think

    def _pause(self):
        lo, hi = self.think
        time.sleep(self.rng.uniform(lo, hi))

    def goto(self, path):
        self.page.goto(f"{self.base}{path}", wait_until="domcontentloaded")
        self._pause()

    def click(self, selector):
        self.page.click(selector, timeout=5000)
        self._pause()

    def fill(self, selector, text):
        self.page.fill(selector, text, timeout=5000)
        self._pause()

    def flush(self):
        """Send this page's telemetry as the page's own script would on an action."""
        try:
            self.page.evaluate("() => window.labTelemetry && window.labTelemetry.flush()")
        except Exception:
            pass


class HumanizedExecutor(Executor):
    """Round 2: a Bezier cursor and per-character typing (W2 Ch3). Jittered think time."""

    def __init__(self, page, base, rng=None, think=(0.6, 2.4)):
        super().__init__(page, base, rng, think)
        self.pos = (self.rng.uniform(100, 900), self.rng.uniform(80, 500))

    def _bezier(self, start, end):
        dx, dy = end[0] - start[0], end[1] - start[1]
        dist = math.hypot(dx, dy) or 1
        nx, ny = -dy / dist, dx / dist
        spread = min(180, max(2, dist * 0.3))
        a, b = self.rng.uniform(0.2, 0.45), self.rng.uniform(0.55, 0.8)
        p1 = (start[0] + dx * a + nx * self.rng.uniform(-spread, spread),
              start[1] + dy * a + ny * self.rng.uniform(-spread, spread))
        p2 = (start[0] + dx * b + nx * self.rng.uniform(-spread, spread),
              start[1] + dy * b + ny * self.rng.uniform(-spread, spread))
        steps = max(14, min(60, int(math.log2(dist + 2) * 7)))
        pts = []
        for i in range(1, steps + 1):
            t = i / steps
            u = 1 - t
            x = u**3 * start[0] + 3 * u*u*t * p1[0] + 3 * u*t*t * p2[0] + t**3 * end[0]
            y = u**3 * start[1] + 3 * u*u*t * p1[1] + 3 * u*t*t * p2[1] + t**3 * end[1]
            pts.append((x + self.rng.gauss(0, 0.4), y + self.rng.gauss(0, 0.4)))
        return pts

    def _scroll_to(self, selector):
        """Bring the control into the viewport the way a hand does: wheel ticks, not scrollIntoView()."""
        for _ in range(8):
            box = self.page.locator(selector).bounding_box()
            if not box:
                return None
            vh = self.page.viewport_size["height"]
            if 60 <= box["y"] and box["y"] + box["height"] <= vh - 60:
                return box
            self.page.mouse.wheel(0, 120 if box["y"] > vh / 2 else -120)
            time.sleep(self.rng.uniform(0.05, 0.15))
        return self.page.locator(selector).bounding_box()

    def _move_to(self, selector):
        box = self._scroll_to(selector)
        if not box:
            return None
        tx = box["x"] + box["width"] * self.rng.uniform(0.3, 0.7)
        ty = box["y"] + box["height"] * self.rng.uniform(0.3, 0.7)
        for px, py in self._bezier(self.pos, (tx, ty)):
            self.page.mouse.move(px, py)
            time.sleep(self.rng.uniform(0.004, 0.014))
        self.pos = (tx, ty)
        return tx, ty

    def click(self, selector):
        at = self._move_to(selector)
        if at is None:
            return self.page.click(selector, timeout=5000)
        time.sleep(self.rng.uniform(0.06, 0.16))
        self.page.mouse.click(*at)
        self._pause()

    def fill(self, selector, text):
        at = self._move_to(selector)
        if at is not None:
            self.page.mouse.click(*at)
        else:
            self.page.click(selector, timeout=5000)
        for ch in text:
            self.page.keyboard.type(ch)
            time.sleep(max(0.03, self.rng.gauss(0.11, 0.04)))
        self._pause()
