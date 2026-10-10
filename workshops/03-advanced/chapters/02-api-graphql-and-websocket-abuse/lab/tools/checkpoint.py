"""Checkpoint — run one round end to end and say whether it passes.

    python tools/checkpoint.py --round 1          # with the server at DEFENSE_LEVEL=1
    python tools/checkpoint.py --round 3 --catch-up   # apply the reference solution

Each round starts from a clean decision log, runs that round's attack and the
legitimate-traffic simulator against the running server, and prints three blocks:
what the bot achieved, what it cost real users, and the defender's per-request
cost. A round passes when the attack is stopped *and* no legitimate client is
blocked. ``--catch-up`` copies solutions/roundN/ over defenses/ (saving a .bak)
for anyone who fell behind; restart the server afterwards so it reloads them.
"""

from __future__ import annotations

import argparse
import importlib
import os
import shutil
import sys

import httpx

HERE = os.path.dirname(os.path.abspath(__file__))
LAB_DIR = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(LAB_DIR, "attacks"))
sys.path.insert(0, os.path.join(LAB_DIR, "tools"))

BASE_URL = os.environ.get("DEMO_URL", "http://127.0.0.1:5000")

ROUNDS = {
    1: {"attack": "round1_scrape", "level": 1, "surface": "rest"},
    2: {"attack": "round2_graphql_batch", "level": 2, "surface": "graphql"},
    3: {"attack": "round3_fragment_amp", "level": 3, "surface": "graphql"},
    4: {"attack": "round4_ws_flood", "level": 4, "surface": "ws"},
    5: {"attack": "round5_token_replay", "level": 5, "surface": "rest"},
}

# Which defense module each round's solution replaces.
SOLUTION_FILES = {
    1: ["rate_cost.py"], 2: ["graphql_limits.py"], 3: ["persisted_queries.py"],
    4: ["ws_guard.py"], 5: ["request_signing.py"],
}


def catch_up(rnd: int):
    src = os.path.join(LAB_DIR, "solutions", f"round{rnd}")
    dst = os.path.join(LAB_DIR, "defenses")
    for name in SOLUTION_FILES[rnd]:
        s = os.path.join(src, name)
        d = os.path.join(dst, name)
        if os.path.exists(d):
            shutil.copy(d, d + ".bak")
        shutil.copy(s, d)
        print(f"  applied {name} (saved {name}.bak)")
    print("Restart the demo server so it reloads the defenses.")


def verdict(rnd: int, s: dict) -> tuple[bool, str]:
    if rnd == 1:
        passed = s["blocked"] > 0 and s["products_scraped"] < 200
        return passed, f"scraped {s['products_scraped']} products, {s['blocked']} requests blocked"
    if rnd == 2:
        passed = s["introspection_blocked"] and s["alias_batch_blocked"]
        return passed, f"introspection_blocked={s['introspection_blocked']} alias_batch_blocked={s['alias_batch_blocked']}"
    if rnd == 3:
        passed = s["blocked"]
        return passed, f"fragment amplification blocked={s['blocked']} ({s['reason'][:40]})"
    if rnd == 4:
        passed = (not s["connected"]) or s["accepted"] < s["sent"]
        return passed, f"connected={s['connected']} accepted={s['accepted']}/{s['sent']}"
    if rnd == 5:
        passed = not s["orders_read"]
        return passed, f"orders_status={s['orders_status']} deceived={s['deceived']}"
    return False, "unknown round"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--round", type=int, required=True, choices=[1, 2, 3, 4, 5])
    ap.add_argument("--base", default=BASE_URL)
    ap.add_argument("--catch-up", action="store_true")
    args = ap.parse_args()
    rnd = args.round

    if args.catch_up:
        catch_up(rnd)
        return

    try:
        status = httpx.get(f"{args.base}/admin/status", timeout=5).json()
    except Exception:
        print(f"Cannot reach the demo store at {args.base}. Start it first:\n"
              f"  DEFENSE_LEVEL={ROUNDS[rnd]['level']} python demo_site/app.py")
        sys.exit(1)
    if status["level"] < ROUNDS[rnd]["level"]:
        print(f"⚠  server is at DEFENSE_LEVEL={status['level']}, round {rnd} needs "
              f">= {ROUNDS[rnd]['level']}. Restart:\n"
              f"  DEFENSE_LEVEL={ROUNDS[rnd]['level']} python demo_site/app.py")

    httpx.post(f"{args.base}/admin/reset", timeout=10)

    attack = importlib.import_module(ROUNDS[rnd]["attack"])
    import legit_traffic
    atk = attack.run(args.base)
    legit = legit_traffic.run(args.base)

    passed, detail = verdict(rnd, atk)
    print(f"\n── Round {rnd} checkpoint (DEFENSE_LEVEL={status['level']}) ──")
    print(f"🔴 Bot traffic:   {detail}")
    print(f"🔵 Real users:    {legit['allowed']}/{legit['total']} served, "
          f"{legit['blocked']} blocked (false positives)")
    dec = httpx.get(f"{args.base}/admin/decisions", params={"limit": 2000}, timeout=10).json()
    costs = [d["cost_ms"] for d in dec if d["surface"] == ROUNDS[rnd]["surface"] and d["cost_ms"]]
    if costs:
        costs.sort()
        p50 = costs[len(costs) // 2]
        print(f"💸 Defender cost: {len(costs)} scored, p50 {p50:.3f} ms/request")
    legit_ok = legit["blocked"] == 0
    ok = passed and legit_ok
    print(f"\n{'✅ PASS' if ok else '❌ FAIL'} — attack {'stopped' if passed else 'NOT stopped'}, "
          f"{'no' if legit_ok else str(legit['blocked'])} false positives")
    if not ok and not passed:
        print(f"Fell behind? Apply the reference defense:\n"
              f"  python tools/checkpoint.py --round {rnd} --catch-up")


if __name__ == "__main__":
    main()
