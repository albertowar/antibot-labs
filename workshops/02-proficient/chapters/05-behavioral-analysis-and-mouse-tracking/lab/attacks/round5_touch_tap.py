"""
Chapter 5, Round 5 attack: be a phone (Section 5.7).

Layers 1-4 exempt touch, on purpose: a finger has no hover path, and a phone's
virtual keyboard sends key "Unidentified" with ~0 ms holds, which no typing
rule may punish. So the scalper stops pretending to be a desktop:

    - a Playwright context with Pixel 7 emulation (has_touch, is_mobile, a phone UA
      and viewport): the page sees pointerType "touch";
    - page.tap() on every field: no path for the mouse rules to judge;
    - IME-style typing over the DevTools Protocol: Input.dispatchKeyEvent with key
      "Unidentified" around Input.insertText, exactly what a virtual keyboard sends
      (Playwright's keyboard API would send real key names, which a phone never does).

Before Layer 5 it scores ~10 (one stray mouse sample at (0, 0) that Playwright's
emulation still dispatches) and reserves. Layer 5 catches what a scripted tap gets
wrong: page.tap() presses and releases in the same millisecond, at the exact
centre of the element.

  --cdp   The attacker's answer: drive the taps with Input.dispatchTouchEvent
          instead, holding each one 60-140 ms, off centre (fingers land low) with a
          finger-sized contact radius. Two more lines per tap, and Layer 5 has
          nothing left. Touch gives a defender far less to measure than a mouse;
          phone traffic leans on device coherence (W2 Ch2), the network stack
          (W2 Ch3) and reputation (Section 5.9).

Expected:
    DEFENSE_LEVEL 0-4  reserved (both)
    DEFENSE_LEVEL 5    default: blocked (instant taps + dead-centre taps)
                       --cdp:   reserved

    python attacks/round5_touch_tap.py [--cdp] [--runs N]
"""

import argparse
import random

from playwright.sync_api import sync_playwright

from _common import FIELDS, SELECTOR, finish, identity, open_drop, report, sleep_ms, submit


def type_ime(cdp, text, rng):
    """What Gboard sends: keydown 'Unidentified' (keyCode 229), the text, keyup."""
    for ch in text:
        cdp.send("Input.dispatchKeyEvent", {"type": "keyDown", "key": "Unidentified", "windowsVirtualKeyCode": 229})
        cdp.send("Input.insertText", {"text": ch})
        cdp.send("Input.dispatchKeyEvent", {"type": "keyUp", "key": "Unidentified", "windowsVirtualKeyCode": 229})
        sleep_ms(rng.lognormvariate(5.5, 0.4))          # ~250 ms between taps on the keyboard


def finger_tap(page, cdp, selector, rng):
    """A tap that holds like a finger: off centre, a contact radius, 60-140 ms down."""
    b = page.locator(selector).bounding_box()
    x = b["x"] + b["width"] * rng.uniform(0.25, 0.7)
    y = b["y"] + b["height"] * rng.uniform(0.5, 0.8)      # fingers land low
    point = {"x": x, "y": y, "radiusX": rng.uniform(8, 14), "radiusY": rng.uniform(9, 16), "force": rng.uniform(0.3, 0.7)}
    cdp.send("Input.dispatchTouchEvent", {"type": "touchStart", "touchPoints": [point]})
    sleep_ms(rng.uniform(60, 140))
    cdp.send("Input.dispatchTouchEvent", {"type": "touchEnd", "touchPoints": []})


def one_run(p, cdp_taps, rng):
    browser, page = open_drop(p, "round5_touch_cdp" if cdp_taps else "round5_touch_tap", **p.devices["Pixel 7"])
    cdp = page.context.new_cdp_session(page)
    who = identity(rng)
    tap = (lambda sel: finger_tap(page, cdp, sel, rng)) if cdp_taps else page.tap
    sleep_ms(rng.uniform(1500, 2500))                        # "read" the page
    for field in FIELDS:
        page.locator(SELECTOR[field]).scroll_into_view_if_needed()
        tap(SELECTOR[field])
        sleep_ms(rng.uniform(300, 700))
        type_ime(cdp, who[field], rng)
        sleep_ms(rng.uniform(300, 700))
    page.locator(SELECTOR["reserve"]).scroll_into_view_if_needed()
    result = submit(page, lambda: tap(SELECTOR["reserve"]))
    browser.close()
    return result


def run(cdp_taps=False, runs=1, verbose=False):
    rng = random.Random()
    results = []
    with sync_playwright() as p:
        for _ in range(runs):
            results.append(one_run(p, cdp_taps, rng))
            if verbose:
                report("round5_touch_cdp" if cdp_taps else "round5_touch_tap", results[-1])
    return results


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--cdp", action="store_true", help="finger-like taps through Input.dispatchTouchEvent")
    ap.add_argument("--runs", type=int, default=1)
    args = ap.parse_args()
    print(f"=== Round 5: touch emulation ({'CDP finger taps' if args.cdp else 'page.tap()'}) ===")
    finish("round5_touch_cdp" if args.cdp else "round5_touch_tap", run(args.cdp, args.runs, verbose=True))
