"""
W2 Ch1 — Bonus Attack: Humanize the Click (Section 1.6, Bonus)

Objective: beat Layer 4 from inside a real browser. Instead of page.click(),
move the mouse along a curved path with jitter and land at a random point
inside the button, the way open-source "humanizer" helpers do.

This beats the two rules this chapter wrote (teleport and dead-centre).
It does not produce human movement: constant-ish speed, no overshoot, no
micro-corrections, perfectly regular timing. Detecting that is the subject
of Chapter 3 (behavioural analysis).

Expected results (verified with patchright 1.63 / Chromium 153):
  - Round 4 (level 5) → 200 on /api/products and /api/cart/add

Run the store first (python demo_site/app.py), then:
    python attacks/bonus_humanized_cursor.py
"""

import math
import random

import round4_patchright
from _common import finish, report


def human_click(page, button):
    """Bezier-ish path from a random start to a random point inside the button."""
    box = button.bounding_box()
    target_x = box["x"] + box["width"] * random.uniform(0.25, 0.75)
    target_y = box["y"] + box["height"] * random.uniform(0.3, 0.7)
    start_x, start_y = random.uniform(50, 400), random.uniform(50, 300)
    control_x = (start_x + target_x) / 2 + random.uniform(-120, 120)
    control_y = (start_y + target_y) / 2 + random.uniform(-80, 80)
    steps = random.randint(25, 40)
    for i in range(steps + 1):
        t = i / steps
        ease = 0.5 - math.cos(math.pi * t) / 2
        x = (1 - ease) ** 2 * start_x + 2 * (1 - ease) * ease * control_x + ease ** 2 * target_x
        y = (1 - ease) ** 2 * start_y + 2 * (1 - ease) * ease * control_y + ease ** 2 * target_y
        page.mouse.move(x + random.uniform(-0.8, 0.8), y + random.uniform(-0.8, 0.8))
        page.wait_for_timeout(random.uniform(6, 18))
    page.wait_for_timeout(random.uniform(80, 200))
    page.mouse.click(target_x, target_y)


def run():
    """Round 4's browser setup with a humanized click."""
    return round4_patchright.run(click=human_click)


if __name__ == '__main__':
    out = run()
    report("Bonus: patchright + humanized cursor", out)
    finish("bonus_humanized_cursor", out)
