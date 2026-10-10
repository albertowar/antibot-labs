"""
W1 Ch9 — Run a drop and print the scoreboard.

Restocks the store (20 hoodies), then releases the 40 shoppers and the
chosen scalper waves at the same moment, each in its own process. When
everyone is done it prints both halves of the result:

  - who got the hoodies: shoppers vs. each wave (what the SERVER sold, not
    what the bots believe: trapped bots see fake confirmations)
  - what it cost: shoppers stopped by a defense (false positives), shoppers
    slowed by proof of work, the attacker's effort, and the gate's latency

    python tools/drop.py --waves 0           # one wave against the shoppers
    python tools/drop.py --waves 0,1,2,3,4   # Drop Day
    python tools/drop.py --waves none        # shoppers only: your false-positive check
    python tools/drop.py --waves 3 --json    # machine-readable (used by checkpoint.py)
"""

import argparse
import glob
import json
import os
import subprocess
import sys
from collections import Counter

from labnet import admin, wait_for_store

LAB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
BROWSER_WAVES = {3, 4}
FALSE_POSITIVE = {"blocked", "stuck_on_challenge", "gave_up", "rate_limited", "bad_form", "over_cap"}


def wave_script(n):
    return glob.glob(os.path.join(LAB, "attacks", f"wave{n}_*.py"))[0]


def run_drop(waves, seed=7):
    """Reset the store, run shoppers + waves concurrently, return the combined result."""
    wait_for_store()
    config = admin("POST", "/admin/reset-drop")["pipeline"]
    python = sys.executable
    procs = {"humans": subprocess.Popen([python, os.path.join(LAB, "tools", "humans.py"), str(seed), "--json"],
                                        stdout=subprocess.PIPE, text=True)}
    for n in waves:
        procs[f"wave{n}"] = subprocess.Popen([python, wave_script(n), "--json"], stdout=subprocess.PIPE, text=True)
    outputs = {}
    for name, proc in procs.items():
        out, _ = proc.communicate(timeout=300)
        try:
            outputs[name] = json.loads(out.strip().splitlines()[-1])
        except (ValueError, IndexError):
            outputs[name] = {"error": f"{name} exited with {proc.returncode}"}
    board = admin("GET", "/admin/scoreboard")
    humans = outputs.pop("humans")
    sold = Counter()
    for actor, n in board["sold"].items():
        sold["humans" if actor.startswith("human:") else actor.split(":")[1]] += n
    return {"pipeline": config, "waves": waves, "sold": dict(sold), "stock_left": board["stock"],
            "humans": humans, "bots": outputs, "outcomes": board["outcomes"], "gate_ms": board["gate_ms"]}


def bot_outcomes(result, wave):
    totals = Counter()
    for actor, outcomes in result["outcomes"].items():
        if actor == f"bot:{wave}":
            totals.update(outcomes)
    return totals


def print_scoreboard(result):
    p = result["pipeline"]
    layers = ", ".join(l.split(".")[0] if l.endswith(".check") else l for l in p["layers"]) or "none"
    waves = ",".join(map(str, result["waves"])) or "none"
    print(f"=== Drop · waves: {waves} · layers: {layers} · challenge: "
          f"{'on' if p['challenge_enabled'] else 'off'} · per-session cap: {p['purchases_per_session'] or 'none'} ===\n")

    sold = result["sold"]
    bots_total = sum(n for k, n in sold.items() if k != "humans")
    split = " · ".join(f"{k} {n}" for k, n in sorted(sold.items()) if k != "humans")
    print(f"Hoodies (20)   shoppers {sold.get('humans', 0):>2}   bots {bots_total:>2}"
          f"{f' ({split})' if split else ''}   unsold {result['stock_left']}")

    humans = result["humans"]
    outcomes = Counter(h["outcome"] for h in humans)
    hurt = [h for h in humans if h["outcome"] in FALSE_POSITIVE or h["outcome"] == "error"]
    hurt_by = Counter(h["persona"] for h in hurt)
    slowed = [h for h in humans if h["pow_seconds"] >= 1.0]
    print(f"Shoppers (40)  bought {outcomes['bought']} · sold out {outcomes['sold_out']} · "
          f"stopped by a defense {len(hurt)}"
          + (f" ({', '.join(f'{k} ×{v}' for k, v in hurt_by.items())})" if hurt else ""))
    if slowed:
        print(f"               slowed ≥1 s by proof of work: {len(slowed)} "
              f"(worst {max(h['pow_seconds'] for h in slowed):.1f} s, {max(h['max_bits'] for h in slowed)} bits)")

    for wave, bot in sorted(result["bots"].items()):
        if "error" in bot:
            print(f"{wave:<14} ERROR: {bot['error']}")
            continue
        server = bot_outcomes(result, wave)
        extras = []
        if bot.get("browser_sessions"):
            extras.append(f"{bot['browser_sessions']} browser sessions")
        if bot.get("pow_seconds"):
            extras.append(f"PoW {bot['pow_seconds']} s")
        print(f"{wave:<14} sold {sold.get(wave, 0):>2} · believes {bot['believed']:>2} · "
              f"{bot['requests']} requests · blocked {server['blocked']} · rate-limited {server['rate_limited']} · "
              f"challenged {server['challenged']} · trapped {server['deceived']}"
              + (f" · {', '.join(extras)}" if extras else ""))

    g = result["gate_ms"]
    if g["median"] is not None:
        print(f"Gate cost      median {g['median']:.2f} ms · p95 {g['p95']:.2f} ms over {g['requests']} requests")


def parse_waves(text):
    return [] if text in ("none", "") else [int(w) for w in text.split(",")]


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Run one drop and print the scoreboard.")
    parser.add_argument("--waves", default="none", help="comma-separated wave numbers (0-4), or none")
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--skip-browser", action="store_true", help="leave out waves 3 and 4 (no Chromium)")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    chosen = [w for w in parse_waves(args.waves) if not (args.skip_browser and w in BROWSER_WAVES)]
    outcome = run_drop(chosen, args.seed)
    if args.json:
        print(json.dumps(outcome))
    else:
        print_scoreboard(outcome)
