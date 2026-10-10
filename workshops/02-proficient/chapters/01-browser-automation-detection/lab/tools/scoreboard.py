"""
W2 Ch1 — Scoreboard (Section 1.6, debrief)

Runs every attack and every legitimate-user profile against the demo site
at its current DEFENSE_LEVEL and prints both sides on one screen:

    bot traffic      which attacks still scrape /api/products and buy via /api/cart
    real users       how many profiles were blocked or scored "suspicious"
    defender cost    server time to score a sensor payload, client time to
                     collect it, and the size of the sensor script

Use it in the debrief, or any time you want the whole picture. For the
pass/fail check at the end of a round, use tools/checkpoint.py.

Run the demo site first, then:
    python tools/scoreboard.py [--skip-browser] [--bonus]
"""

import argparse
import gzip
import importlib
import json
import os
import statistics
import sys
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
LAB = os.path.join(HERE, "..")
sys.path.insert(0, os.path.join(LAB, "attacks"))
sys.path.insert(0, HERE)

import legit_traffic  # noqa: E402

BASE_URL = os.environ.get("DEMO_URL", "http://localhost:5000")
SENSOR_JS = os.path.join(LAB, "demo_site", "static", "sensor.js")

# (module, kwargs, label, round introduced, first level that blocks the scrape,
#  first level that blocks the cart, needs a browser). None = never blocked here.
ATTACKS = [
    ("round0_httpx_scraper", {}, "httpx, default headers", 0, 0, 0, False),
    ("round0_playwright_default", {}, "Playwright defaults", 0, 0, 0, True),
    ("round1_playwright_cdp_override", {}, "Playwright + CDP identity", 1, 1, 1, True),
    ("round2_flags_off", {}, "+ automation flags off", 2, 2, 2, True),
    ("round3_stealth_plugin", {}, "+ playwright-stealth", 3, 3, 3, True),
    ("round4_patchright", {}, "patchright, new headless", 4, None, 4, True),
    ("round4_patchright", {"vanilla": True}, "same, plain Playwright", 4, 1, 1, True),
    ("round5_forged_sensor", {}, "forged sensor (no browser)", 5, None, None, False),
]
BONUS = [
    ("bonus_humanized_cursor", {}, "patchright + humanized cursor", 6, None, None, True),
    ("bonus_selenium", {}, "Selenium + ChromeDriver", 6, 1, 1, True),
]


def server_level():
    with urllib.request.urlopen(f"{BASE_URL}/sensor-check", timeout=5) as r:
        return json.loads(r.read())["level"]


def blocked_at(first, level):
    return first is not None and level >= first


def run_attack(module, kwargs):
    try:
        results = importlib.import_module(module).run(**kwargs)
    except Exception as e:                 # a broken attack must not hide the others
        return {"error": f"{type(e).__name__}: {str(e).splitlines()[0][:120]}"}
    return {r["path"]: r for r in results}


def fmt(status):
    if status == 200:
        return "200 ✅"
    if status == 403:
        return "403 ⛔"
    return "  -  "


def measure_attacks(level, attacks, skip_browser=False):
    rows = []
    for module, kwargs, label, _, first_scrape, first_cart, browser in attacks:
        if browser and skip_browser:
            rows.append({"label": label, "skipped": True})
            continue
        got = run_attack(module, kwargs)
        rows.append({
            "label": label, "module": module, "error": got.get("error"),
            "scrape": (got.get("/api/products") or {}).get("status"),
            "cart": (got.get("/api/cart") or {}).get("status"),
            "expect_scrape": 403 if blocked_at(first_scrape, level) else 200,
            "expect_cart": None if blocked_at(first_scrape, level) else (403 if blocked_at(first_cart, level) else 200),
            "reasons": [reason for r in got.values() if isinstance(r, dict) for reason in r.get("reasons", [])],
        })
    return rows


def attack_ok(row):
    return not row.get("error") and row["scrape"] == row["expect_scrape"] and row["cart"] == row["expect_cart"]


def print_attacks(rows):
    print(f"  {'Attack':<32} {'/api/products':<14} {'/api/cart':<10}")
    for row in rows:
        if row.get("skipped"):
            print(f"  ⏭️  {row['label']:<29} skipped (--skip-browser)")
            continue
        if row.get("error"):
            print(f"  ❌ {row['label']:<29} ERROR {row['error']}")
            continue
        mark = "✅" if attack_ok(row) else "❌"
        print(f"  {mark} {row['label']:<29} {fmt(row['scrape']):<14} {fmt(row['cart']):<10}")
        if not attack_ok(row):
            print(f"       expected /api/products {row['expect_scrape']}, /api/cart {row['expect_cart'] or '-'}")
            for reason in row["reasons"][:4]:
                print(f"       - {reason}")


def print_legit(results):
    blocked = [r for r in results if legit_traffic.is_blocked(r)]
    unexpected = [r for r in blocked if not r["expected_cost"]]
    suspicious = [r for r in results if r["verdict"] == "suspicious" and not legit_traffic.is_blocked(r)]
    print(f"  {'❌' if unexpected else '✅'} {len(blocked)}/{len(results)} real-user profiles blocked")
    for r in blocked:
        tag = "accepted cost" if r["expected_cost"] else "FALSE POSITIVE"
        print(f"       {r['profile']}: {tag}: {'; '.join(r['reasons'][:2])}")
    for r in suspicious:
        print(f"  🟡 {r['profile']} scored suspicious ({r['score']}): {'; '.join(r['reasons'][:2])}")
    return unexpected


def print_cost(results):
    sensor_ms = [r["sensor_ms"] for r in results if r["sensor_ms"] is not None]
    collect_ms = [r["collect_ms"] for r in results if r["collect_ms"] is not None]
    with open(SENSOR_JS, "rb") as f:
        raw = f.read()
    print(f"  sensor scoring (server): median {statistics.median(sensor_ms):.2f} ms per payload"
          if sensor_ms else "  sensor scoring (server): not measured")
    if collect_ms:
        print(f"  sensor collection (client, from profiles): median {statistics.median(collect_ms):.0f} ms, "
              f"max {max(collect_ms):.0f} ms before the product list can load")
    print(f"  sensor.js: {len(raw) / 1024:.1f} KB ({len(gzip.compress(raw)) / 1024:.1f} KB gzipped), "
          f"+1 request (POST /api/sensor) per page view")


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    parser.add_argument("--skip-browser", action="store_true", help="skip browser-based attacks")
    parser.add_argument("--bonus", action="store_true", help="also run the bonus attacks")
    args = parser.parse_args()
    try:
        level = server_level()
    except OSError:
        print(f"❌ Demo site not reachable on {BASE_URL}. Is it running?")
        return 1
    print(f"=== Scoreboard at DEFENSE_LEVEL={level} ===\n\nBot traffic")
    print_attacks(measure_attacks(level, ATTACKS + (BONUS if args.bonus else []), args.skip_browser))
    print("\nReal users")
    results = legit_traffic.run(BASE_URL)
    print_legit(results)
    print("\nDefender cost")
    print_cost(results)
    return 0


if __name__ == '__main__':
    sys.exit(main())
