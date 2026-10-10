"""
Chapter 3, Round 3 attack: the humanizer (Section 3.5).

Curved Bezier paths, Fitts-scaled step counts, overshoot on long moves,
random click points and Gaussian typing (attacks/humanize.py). This beats
every Layer 2 rule: paths are curved, step sizes vary, key timings vary.

Two flavours, both run by the checkpoint:
    --ease    smoothstep easing (slow start and stop)
    default   no easing (ghost-cursor style: uniform in t)

Expected:
    DEFENSE_LEVEL 0-2  reserved (both flavours)
    DEFENSE_LEVEL >= 3 default: blocked (no deceleration + symmetric + Gaussian typing)
                       --ease:  challenged or blocked (symmetric + Gaussian typing)

    python attacks/round3_humanizer.py [--ease] [--runs N]
"""

import argparse
import random

from playwright.sync_api import sync_playwright

from common import identity, open_drop, report, sleep_ms, wait_result
from humanize import Cursor, human_type


def one_run(p, ease):
    label = "round3_humanizer_ease" if ease else "round3_humanizer"
    browser, page = open_drop(p, label)
    cursor = Cursor(page, ease=ease)
    who = identity()
    sleep_ms(random.uniform(600, 1200))
    for field in ("name", "email", "size"):
        cursor.click(f"#{field}")
        sleep_ms(random.uniform(150, 400))
        human_type(page, who[field])
        sleep_ms(random.uniform(200, 600))
    cursor.click("#reserve")
    result = wait_result(page)
    browser.close()
    return result


def run(ease=False, runs=2, verbose=False):
    results = []
    with sync_playwright() as p:
        for _ in range(runs):
            result = one_run(p, ease)
            results.append(result)
            if verbose:
                report("round3_humanizer" + ("_ease" if ease else ""), result)
    return results


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--ease", action="store_true")
    ap.add_argument("--runs", type=int, default=2)
    args = ap.parse_args()
    print(f"=== Round 3: Bezier humanizer ({'eased' if args.ease else 'no easing'}) ===")
    run(args.ease, args.runs, verbose=True)
