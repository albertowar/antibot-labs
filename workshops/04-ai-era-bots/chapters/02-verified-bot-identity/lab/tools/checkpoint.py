"""Checkpoint: run one round end to end and say whether it passes.

    python tools/checkpoint.py --round 2              # server at DEFENSE_LEVEL=2
    python tools/checkpoint.py --round 2 --catch-up   # apply the reference solution

Each round resets both the store and the mock internet, runs the round's attack
and the legitimate cohorts, and prints four lines: what the impostor got, which
genuine crawlers were admitted, how many humans were blocked, and what the gate
cost. A round passes when the impostor is out of the fast lane, no human is
blocked, and every genuine crawler the level *can* verify is admitted. Crawlers
the level cannot verify yet are listed as expected false positives, because that
cost is the point of the next round.
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
sys.path.insert(0, HERE)

BASE_URL = os.environ.get("DEMO_URL", "http://127.0.0.1:5000")
MOCK_URL = os.environ.get("MOCK_URL", "http://127.0.0.1:5001")

ROUNDS = {
    1: {"attack": "round1_ua_spoof", "level": 1, "solution": ["rdns.py"]},
    2: {"attack": "round2_ptr_spoof", "level": 2, "solution": ["rdns.py"]},
    3: {"attack": "round3_range_squat", "level": 3, "solution": ["ip_ranges.py"]},
    4: {"attack": "round1_ua_spoof", "level": 4, "solution": ["web_bot_auth.py"]},
    5: {"attack": "round4_replay", "level": 5, "solution": ["web_bot_auth.py"]},
}
# Genuine crawlers a level cannot verify yet: expected (and reported) false positives.
EXPECTED_REJECTED = {
    1: {"gptbot", "gptbot-new", "claudebot", "perplexitybot", "chatgpt-agent"},
    2: {"gptbot", "gptbot-new", "claudebot", "perplexitybot", "chatgpt-agent"},
    3: {"chatgpt-agent"},
    4: set(),
    5: set(),
}


def catch_up(rnd: int):
    for name in ROUNDS[rnd]["solution"]:
        src = os.path.join(LAB_DIR, "solutions", f"round{rnd}", name)
        dst = os.path.join(LAB_DIR, "defenses", name)
        if os.path.exists(dst):
            shutil.copy(dst, dst + ".bak")
        shutil.copy(src, dst)
        print(f"  applied solutions/round{rnd}/{name} -> defenses/{name} (saved {name}.bak)")
    print("Restart the demo store so it reloads the defenses.")


def attack_verdict(rnd: int, atk: dict) -> tuple[bool, str]:
    if rnd == 1:
        return atk["spoof"]["scraped"] < 200, f"UA spoof scraped {atk['spoof']['scraped']}/200"
    if rnd == 2:
        return atk["forged"]["scraped"] < 200, f"forged PTR scraped {atk['forged']['scraped']}/200"
    if rnd == 3:
        ok = atk["squat"]["scraped"] < 200 and atk["gptbot_claim"]["scraped"] < 200
        return ok, f"shared-infra squat {atk['squat']['scraped']}/200, GPTBot claim {atk['gptbot_claim']['scraped']}/200"
    if rnd == 4:
        return atk["spoof"]["scraped"] < 200, f"UA spoof still {atk['spoof']['scraped']}/200"
    if rnd == 5:
        ok = atk["stale"]["scraped"] == 0 and atk["fresh"]["scraped"] <= 1
        return ok, f"stale replay {atk['stale']['scraped']}/200, fresh replay {atk['fresh']['scraped']}/200"
    return False, "unknown round"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--round", type=int, required=True, choices=sorted(ROUNDS))
    ap.add_argument("--base", default=BASE_URL)
    ap.add_argument("--mock", default=MOCK_URL)
    ap.add_argument("--catch-up", action="store_true")
    args = ap.parse_args()
    rnd = args.round
    if args.catch_up:
        catch_up(rnd)
        return

    try:
        status = httpx.get(f"{args.base}/admin/status", timeout=5).json()
        httpx.get(f"{args.mock}/stats", timeout=5).raise_for_status()
    except Exception:
        print(f"Cannot reach the store at {args.base} or the mock internet at {args.mock}. Start both:\n"
              f"  python tools/mock_internet.py\n  DEFENSE_LEVEL={ROUNDS[rnd]['level']} python demo_site/app.py")
        sys.exit(1)
    if status["level"] != ROUNDS[rnd]["level"]:
        print(f"⚠  store is at DEFENSE_LEVEL={status['level']}, round {rnd} expects {ROUNDS[rnd]['level']}. Restart:\n"
              f"  DEFENSE_LEVEL={ROUNDS[rnd]['level']} python demo_site/app.py")

    httpx.post(f"{args.mock}/reset", timeout=5)
    httpx.post(f"{args.base}/admin/reset", timeout=5)
    attack = importlib.import_module(ROUNDS[rnd]["attack"])
    atk = attack.run(args.base) if rnd in (1, 3, 4) else attack.run(args.base, args.mock)
    httpx.post(f"{args.base}/admin/reset", params={"scope": "budgets"}, timeout=5)
    import legit_traffic
    legit = legit_traffic.run(args.base, quiet=True)

    passed, detail = attack_verdict(rnd, atk)
    rejected = {n for n, v in legit["crawlers"].items() if not v["admitted"]}
    unexpected = rejected - EXPECTED_REJECTED[rnd]
    expected = rejected & EXPECTED_REJECTED[rnd]
    rows = httpx.get(f"{args.base}/admin/decisions", params={"limit": 5000}, timeout=10).json()
    claimant = sorted(r["cost_ms"] for r in rows if r["claim"] or r["method"] == "web-bot-auth")
    human = sorted(r["cost_ms"] for r in rows if r["actor"] == "legit-human")

    print(f"\n── Round {rnd} checkpoint (DEFENSE_LEVEL={status['level']}) ──")
    print(f"🔴 Impostors:        {detail}")
    print(f"🕷  Genuine crawlers: {legit['crawlers_admitted']}/{legit['crawlers_total']} admitted"
          + (f"  (expected at L{status['level']}: {', '.join(sorted(expected))} not verifiable)" if expected else "")
          + (f"  ❌ unexpectedly rejected: {', '.join(sorted(unexpected))}" if unexpected else ""))
    print(f"👤 Humans:           {legit['humans_ok']}/{legit['humans_total']} served, {legit['humans_blocked']} blocked")
    if claimant:
        mock = httpx.get(f"{args.mock}/stats", timeout=5).json()
        print(f"💸 Gate cost:        claimant requests p50 {claimant[len(claimant)//2]:.2f} ms / "
              f"p95 {claimant[int(len(claimant)*0.95)]:.2f} ms; humans p50 {human[len(human)//2] if human else 0:.3f} ms; "
              f"mock internet: {mock['ptr']} PTR + {mock['a']} A lookups, {mock['ranges']} range fetches, {mock['dir']} directory fetches")
    if rnd == 4:
        extra = importlib.import_module("round4_self_signed_agent").run(args.base, args.mock)
        print(f"ℹ  L4 is naive on purpose: a self-signed agent got {extra['scraped']}/200 (Round 5 closes this)")
    ok = passed and legit["humans_blocked"] == 0 and not unexpected
    print(f"\n{'✅ PASS' if ok else '❌ FAIL'} — impostor {'out of the fast lane' if passed else 'STILL in the fast lane'}, "
          f"{legit['humans_blocked']} humans blocked, {len(unexpected)} genuine crawlers wrongly rejected")
    if not ok:
        print(f"Fell behind? Apply the reference defense:\n  python tools/checkpoint.py --round {rnd} --catch-up")


if __name__ == "__main__":
    main()
