"""
Run a drop and print the scoreboard.

Restocks the store (20 hoodies), then releases the 40 shoppers (tools/personas_ch9.py) and the chosen
scalper rounds' bots at the same moment, each bot in its own process. When everyone is done it prints
both halves of the result:

  - who got the hoodies: shoppers vs. each bot, as the SERVER sold them (not what the bots believe: a
    trapped bot is told it bought)
  - what it cost: shoppers stopped by a defense (false positives), shoppers slowed by a proof of work,
    the bot's effort, and the gate's latency

    python tools/drop.py --waves 2           # one scalper against the shoppers, at the store's current level
    python tools/drop.py --level 2 --waves 2 # set the defense level first (POST /lab/level), then the same
    python tools/drop.py --waves 0,1,2,3,4   # Drop Day
    python tools/drop.py --waves none        # shoppers only: your false-positive check
    python tools/drop.py --waves 3 --json    # machine-readable (checkpoint.py uses run_drop() directly)

The "waves" are the attack scripts attacks/round0_* .. round4_*: wave N is the bot that beats Round N.
"""

import argparse
import json
import os
import subprocess
import sys
import threading
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
LAB = os.path.abspath(os.path.join(HERE, ".."))
sys.path.insert(0, HERE)

import personas_ch9  # noqa: E402,F401  (registers the drop_day scenario)
import population  # noqa: E402
from labclient import BASE_URL, admin, reset, set_level, wait_for_store  # noqa: E402

STOCK = 20
SEED = int(os.environ.get("DROP_SEED", "7"))
WAVES = {
    0: ("attacks/round0_naive_scalper.py", "bot:r0_scalper"),
    1: ("attacks/round1_cloud_fleet.py", "bot:r1_fleet"),
    2: ("attacks/round2_residential_filler.py", "bot:r2_filler"),
    3: ("attacks/round3_session_minting.py", "bot:r3_minter"),
    4: ("attacks/round4_full_browser.py", "bot:r4_browser"),
}
BROWSER_WAVES = {3, 4}
HURT = population.HURT | {"error"}


def _decisions():
    return admin("GET", "/lab/decisions", params={"limit": 5000})["items"]


def _bot_json(proc, out):
    try:
        return json.loads(out.strip().splitlines()[-1])
    except (ValueError, IndexError):
        return {"error": f"exited with {proc.returncode}"}


def run_drop(waves, seed=SEED, stock=STOCK):
    """Reset the store, run the shoppers and the chosen waves concurrently, return the combined result."""
    status = wait_for_store()
    reset(stock=stock)
    env = dict(os.environ, DEMO_URL=BASE_URL, PYTHONPATH=HERE + os.pathsep + os.environ.get("PYTHONPATH", ""))
    procs = {n: subprocess.Popen([sys.executable, os.path.join(LAB, WAVES[n][0])], env=env, cwd=LAB,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) for n in waves}
    people = []
    shoppers = threading.Thread(target=lambda: people.extend(population.run("drop_day", seed=seed, quiet=True)))
    shoppers.start()
    bots = {}
    for n, proc in procs.items():
        out, err = proc.communicate(timeout=600)
        bots[n] = _bot_json(proc, out)
        if "error" in bots[n]:
            bots[n]["stderr"] = err[-400:]
    shoppers.join()

    rows = _decisions()
    sold, outcomes, ms = Counter(), {}, []
    for d in rows:
        who = "humans" if d["actor"].startswith("human:") else d["actor"]
        outcomes.setdefault(who, Counter())[d["outcome"]] += 1
        if d["outcome"] == "purchased":
            sold[who] += 1
        ms.append(d["ms"] or 0)
    ms.sort()
    pct = (lambda q: ms[min(len(ms) - 1, int(q * len(ms)))] if ms else None)
    board = admin("GET", "/lab/scoreboard")["summary"]
    return {"level": status["level"], "waves": list(waves), "sold": dict(sold), "stock_left": board["drops"].get("lab-hoodie-1"),
            "humans": people, "bots": bots, "outcomes": {k: dict(v) for k, v in outcomes.items()},
            "gate_ms": {"median": pct(0.5), "p95": pct(0.95), "requests": len(ms)}}


def bot_sold(result, wave):
    return result["sold"].get(WAVES[wave][1], 0)


def hurt_personas(result):
    """The personas of shoppers a defense stopped, faked or made give up."""
    return sorted({h["persona"] for h in result["humans"] if h.get("outcome") in HURT})


def print_scoreboard(result):
    waves = ",".join(map(str, result["waves"])) or "none"
    print(f"=== Drop · level {result['level']} · waves: {waves} ===\n")
    sold = result["sold"]
    bots_total = sum(n for k, n in sold.items() if k != "humans")
    split = " · ".join(f"{WAVES[w][1].split(':')[1]} {sold.get(WAVES[w][1], 0)}" for w in result["waves"])
    print(f"Hoodies ({STOCK})   shoppers {sold.get('humans', 0):>2}   bots {bots_total:>2}"
          f"{f' ({split})' if split else ''}   unsold {result['stock_left']}")
    people = result["humans"]
    by = Counter(h.get("outcome") for h in people)
    hurt = [h for h in people if h.get("outcome") in HURT]
    hurt_by = Counter(h["persona"] for h in hurt)
    print(f"Shoppers ({len(people)})  bought {by['bought']} · sold out {by['sold_out']} · stopped by a defense {len(hurt)}"
          + (f" ({', '.join(f'{k} x{v}' for k, v in sorted(hurt_by.items()))})" if hurt else ""))
    slow = personas_ch9.slowed(people)
    if slow:
        print(f"               slowed >=1 s by proof of work: {len(slow)} (worst {max(h['pow']['wait_s'] for h in slow):.1f} s, "
              f"{max(h['pow']['bits'] for h in slow)} bits)")
    for w in result["waves"]:
        name = WAVES[w][1]
        bot = result["bots"][w]
        if "error" in bot:
            print(f"{name:<15}ERROR: {bot['error']} {bot.get('stderr', '')}")
            continue
        o = result["outcomes"].get(name, {})
        extras = [f"{bot['browser_sessions']} browser sessions"] if bot.get("browser_sessions") else []
        if bot.get("solves"):
            extras.append(f"PoW {bot['solves']} solves, {bot['cpu_s']} CPU-s")
        print(f"{name:<15}sold {result['sold'].get(name, 0):>2} · believes {bot['believed']:>2} · {o and sum(o.values())} requests · "
              f"blocked {o.get('blocked', 0)} · rate-limited {o.get('rate_limited', 0)} · challenged {o.get('challenged', 0)} · "
              f"trapped {o.get('deceived', 0)}" + (f" · {', '.join(extras)}" if extras else ""))
    g = result["gate_ms"]
    if g["median"] is not None:
        print(f"Gate cost      median {g['median']:.2f} ms · p95 {g['p95']:.2f} ms over {g['requests']} requests")


def parse_waves(text):
    return [] if text in ("none", "") else [int(w) for w in text.split(",")]


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Run one drop and print the scoreboard.")
    ap.add_argument("--waves", default="none", help="comma-separated wave numbers (0-4), or none")
    ap.add_argument("--level", type=int, default=None, help="set DEFENSE_LEVEL (0-4) before the drop")
    ap.add_argument("--seed", type=int, default=SEED)
    ap.add_argument("--skip-browser", action="store_true", help="leave out waves 3 and 4 (no Chromium)")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    if args.level is not None:
        wait_for_store()
        set_level(args.level)
    chosen = [w for w in parse_waves(args.waves) if not (args.skip_browser and w in BROWSER_WAVES)]
    outcome = run_drop(chosen, args.seed)
    if args.json:
        print(json.dumps(outcome, default=str))
    else:
        print_scoreboard(outcome)
