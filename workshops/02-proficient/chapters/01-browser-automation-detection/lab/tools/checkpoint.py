"""
Round checkpoint for Chapter 1 (Browser Automation Detection). Declares the rounds and hands over to
checkpoint_core.

    python tools/checkpoint.py --round 3              # set the round's level, run every bot next to the 40 shoppers
    python tools/checkpoint.py --round 3 --catch-up   # install solutions/round1..3 first (your files kept as .bak)
    python tools/checkpoint.py --restore              # put your own files back
    python tools/checkpoint.py --all --markdown       # every round (the README's expected-results table)

One offset to remember: Round N runs at DEFENSE_LEVEL N+1 (defenses/ladder.py). Level 0 is the bare
store; W1's header rules are level 1, Round 0's starting point.

Every round runs every bot of the chapter, so you see both what the current layers stop and what
still gets through. Each bot reports its two API calls (`/api/products`, `/api/cart/add`); the
expectation is "full" (both 200), "partial" (the catalogue but not the cart) or "blocked".

Next to the bots, the store's 40 shoppers each replay a real-browser profile (tools/personas_ch1.py):
a blocked shopper fails the round, except the no-JavaScript one from Round 1 on (an accepted cost).
The checkpoint also runs your TODO function on known inputs, and reports what the defense costs
(gate time on the API, the sensor's collection time and script size).

Needs the browsers: pip install -r requirements-browser.txt && python -m playwright install chromium &&
python -m patchright install chromium
"""

import gzip
import importlib
import os
import statistics
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import personas_ch1  # noqa: E402,F401  (registers the "sensor_shop" scenario)
import profile_replay  # noqa: E402
from checkpoint_core import LAB, Round, main  # noqa: E402

sys.path.insert(0, LAB)
SENSOR_JS = os.path.join(LAB, "demo_site", "static", "js", "sensor.js")

# name -> (script, first ROUND that blocks the catalogue, first ROUND that blocks the cart); None = never here
BOTS = {
    "round0_httpx_scraper": ("attacks/round0_httpx_scraper.py", 0, 0),
    "round0_playwright_default": ("attacks/round0_playwright_default.py", 0, 0),
    "round1_playwright_cdp_override": ("attacks/round1_playwright_cdp_override.py", 1, 1),
    "round2_flags_off": ("attacks/round2_flags_off.py", 2, 2),
    "round3_stealth_plugin": ("attacks/round3_stealth_plugin.py", 3, 3),
    "round4_patchright": ("attacks/round4_patchright.py", None, 4),
    "round4_patchright_vanilla": ("attacks/round4_patchright.py --vanilla", 1, 1),
    "round5_forged_sensor": ("attacks/round5_forged_sensor.py", None, None),
}
LAYER_MODULES = {1: "automation_artifacts", 2: "consistency", 3: "lie_detection", 4: "interaction"}
SOLUTIONS = {1: ("defenses/automation_artifacts.py",), 2: ("defenses/consistency.py",),
             3: ("defenses/lie_detection.py",), 4: ("defenses/interaction.py",)}


def expect(rnd):
    out = {}
    for name, (_, scrape, cart) in BOTS.items():
        scrape_stopped = scrape is not None and rnd >= scrape
        cart_stopped = cart is not None and rnd >= cart
        out[name] = "blocked" if scrape_stopped else ("partial" if cart_stopped else "full")
    return out


DESKTOP_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/153.0.0.0 Safari/537.36")
MOBILE_UA = ("Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 "
             "(KHTML, like Gecko) Chrome/153.0.0.0 Mobile Safari/537.36")


def geometry(outer_w, outer_h, inner_w, inner_h):
    return {"outer_w": outer_w, "outer_h": outer_h, "inner_w": inner_w, "inner_h": inner_h}


def realm(ua, languages=("en-US", "en")):
    return {"ua": ua, "platform": "Win32", "languages": list(languages), "hardware_concurrency": 8}


# Round -> (function name, [(description, input, should_score_points)])
UNIT_CHECKS = {
    1: ("check_webdriver", [
        ("navigator.webdriver true", {"webdriver": True}, True),
        ("navigator.webdriver false", {"webdriver": False}, False),
        ("navigator.webdriver missing (old Safari)", {"webdriver": None}, False),
    ]),
    2: ("check_headless_shape", [
        ("desktop, outer == viewport", {"ua": DESKTOP_UA, "geometry": geometry(1280, 720, 1280, 720)}, True),
        ("desktop, outer is 0x0", {"ua": DESKTOP_UA, "geometry": geometry(0, 0, 1280, 720)}, True),
        ("desktop window with toolbars", {"ua": DESKTOP_UA, "geometry": geometry(1920, 1032, 1920, 945)}, False),
        ("phone (no outer chrome is normal)", {"ua": MOBILE_UA, "geometry": geometry(412, 915, 412, 915)}, False),
    ]),
    3: ("check_realm_consistency", [
        ("Worker UA differs", {**realm(DESKTOP_UA), "webdriver": False,
                               "worker": realm(DESKTOP_UA.replace("Chrome/", "HeadlessChrome/"))}, True),
        ("Worker languages differ", {**realm(DESKTOP_UA), "webdriver": False,
                                     "worker": realm(DESKTOP_UA, ("en-US",))}, True),
        ("iframe UA differs", {**realm(DESKTOP_UA), "webdriver": False, "worker": realm(DESKTOP_UA),
                               "iframe": {"ua": "x", "platform": "Win32", "webdriver": False}}, True),
        ("all realms agree", {**realm(DESKTOP_UA), "webdriver": False, "worker": realm(DESKTOP_UA),
                              "iframe": {"ua": DESKTOP_UA, "platform": "Win32", "webdriver": False}}, False),
        ("Worker blocked (CSP)", {**realm(DESKTOP_UA), "webdriver": False, "worker": {"error": "timeout"}}, False),
    ]),
    4: ("check_teleport", [
        ("1 pointer move before the click", {"moves_before": 1}, True),
        ("0 pointer moves", {"moves_before": 0}, True),
        ("57 pointer moves", {"moves_before": 57}, False),
    ]),
}




def your_code(rnd):
    """The function you finish in each round, against known inputs (rounds 1..rnd)."""
    def check(board, results, attacks):
        bad = []
        for r in range(1, min(rnd, 4) + 1):
            module = importlib.import_module(f"defenses.{LAYER_MODULES[r]}")
            importlib.reload(module)
            func_name, cases = UNIT_CHECKS[r]
            func = getattr(module, func_name)
            for description, data, should_fire in cases:
                points, _ = func(data)
                if (points > 0) != should_fire:
                    bad.append(f"{LAYER_MODULES[r]}.{func_name}: {description}: "
                               f"expected {'points' if should_fire else '0 points'}, got {points}")
        print("\nyour code: " + ("OK" if not bad else f"{len(bad)} case(s) wrong (finish the TODO, or --catch-up)"))
        for line in bad:
            print("  " + line)
        return (not bad, "; ".join(bad[:3]))
    return check


def shoppers(board, results, attacks):
    """Who replayed which profile, who was suspicious (20-39), and what the defense costs."""
    print("\nshoppers (one real-browser profile each)")
    for r in sorted(results, key=lambda r: r.get("profile", "")):
        if r.get("outcome") != "browsed" or (r.get("score") or 0) >= 20:
            print(f"  {r.get('outcome', '?'):<8} {r.get('profile', '?'):<34} score {r.get('score')}  {r.get('signals', '')}")
    gate = [r["gate_ms"] for r in results if r.get("gate_ms") is not None]
    collect = [p["signals"].get("collect_ms") for p in profile_replay.load_profiles()
               if p.get("signals") and p["signals"].get("collect_ms") is not None]
    raw = open(SENSOR_JS, "rb").read()
    print("defender cost: gate on /api/products median "
          f"{statistics.median(gate):.2f} ms, max {max(gate):.2f} ms" if gate else "defender cost: -")
    print(f"               sensor collection {statistics.median(collect):.0f} ms median in the browser (from the profiles); "
          f"sensor.js {len(raw) / 1024:.1f} KB, {len(gzip.compress(raw)) / 1024:.1f} KB gzipped" if collect else "")
    return (True, "")


def make_round(n, description, level=None):
    return Round(level=n + 1 if level is None else level, description=description, scenario="sensor_shop",
                 attacks={name: script for name, (script, _, _) in BOTS.items()}, expect=expect(n),
                 allowed_fp=("no_js",) if n >= 1 else (), bot_success_max=1.0,
                 extra_checks=([your_code(n)] if n >= 1 else []) + [shoppers],
                 solutions=SOLUTIONS.get(n, ()))


ROUNDS = {
    0: make_round(0, "W1's header rules only (level 1)"),
    1: make_round(1, "the sensor gate + automation artifacts (level 2)"),
    2: make_round(2, "+ consistency (level 3)"),
    3: make_round(3, "+ lie detection (level 4)"),
    4: make_round(4, "+ interaction evidence on the cart (level 5)"),
    5: make_round(5, "forge the sensor: integrity is the next chapter (level 5)", level=5),
}

if __name__ == "__main__":
    main(ROUNDS)
