"""
Chapter 3, Round 2 attack: move the mouse, press real keys (Section 3.4).

The scalper read the Round 1 reasons and fixes each one:
    - mouse.move(x, y, steps=25) produces 25 real pointermove events, so
      there is "pointer travel" before every click;
    - it aims at a random point near the centre, not the exact centre;
    - keyboard.type(text, delay=100) sends real keydown/keyup pairs
      (Playwright holds each key for `delay` ms, then releases it);
    - it waits so the form takes several seconds.

What it doesn't fix: steps are equal slices of a straight line, and every
key is held exactly 100 ms with a ~2 ms gap. Ruler and metronome.

Expected:
    DEFENSE_LEVEL 0-1  reserved
    DEFENSE_LEVEL >= 2 blocked: ruler-straight approach + metronome typing

    python attacks/round2_linear_steps.py
"""

import random

from playwright.sync_api import sync_playwright

from _common import FIELDS, box, finish, identity, open_drop, report, sleep_ms, submit


def move_and_click(page, field):
    b = box(page, field)
    x = b["x"] + b["width"] / 2 + random.uniform(-8, 8)
    y = b["y"] + b["height"] / 2 + random.uniform(-4, 4)
    page.mouse.move(x, y, steps=25)
    page.mouse.down()
    page.mouse.up()


def run(verbose=False):
    with sync_playwright() as p:
        browser, page = open_drop(p, "round2_linear_steps")
        who = identity()
        sleep_ms(800)
        for field in FIELDS:
            move_and_click(page, field)
            page.keyboard.type(who[field], delay=100)
            sleep_ms(300)
        result = submit(page, lambda: move_and_click(page, "reserve"))
        browser.close()
    if verbose:
        report("round2_linear_steps", result)
    return [result]


if __name__ == "__main__":
    print("=== Round 2: mouse.move(steps=25) + keyboard.type(delay=100) ===")
    finish("round2_linear_steps", run(verbose=True))
