"""
Round checkpoint for Chapter 6 (The Price of a Page). Declares the rounds and hands over to checkpoint_core.

    python tools/checkpoint.py --round 3              # set the level, run the round's attacks next to the shoppers
    python tools/checkpoint.py --round 3 --catch-up   # install solutions/round1..3 first
    python tools/checkpoint.py --all --markdown       # every round (the expected-results table)

PoW rarely *blocks* a paying bot, so every round reports price as well as success: CPU-seconds
and dollars per 1,000 products for the bot, and for the shoppers the wait (hashes / device rate)
and who gave up. The attacks run as subprocesses, one after the other, while the 40 shoppers
(tools/population.py + tools/personas_ch6.py) browse and buy. `DESKTOP_MHS` (default 4.0) is the
desktop browser's hash rate; set it from your own /lab/pow/bench number.

Round 5 needs Playwright (`pip install -r requirements-browser.txt`, `python -m playwright install chromium`).
"""

import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import personas_ch6  # noqa: E402  (registers the shoppers' PoW hook)
from checkpoint_core import LAB, Round, main  # noqa: E402
from labclient import BASE_URL  # noqa: E402
from pow_client import USD_PER_VCPU_HOUR  # noqa: E402

LAST = {}       # attack name -> its JSON result (checkpoint_core does not hand attack output to checks)


def attack(*scripts):
    """One round's attacks, run one after the other. A script may carry flags: 'round2_solve_once_replay.py --share'."""
    def run():
        for spec in scripts:
            script, *flags = spec.split()
            env = dict(os.environ, DEMO_URL=BASE_URL, PYTHONPATH=HERE)
            r = subprocess.run([sys.executable, os.path.join(LAB, "attacks", script), *flags], env=env, cwd=LAB,
                               capture_output=True, text=True, timeout=900)
            if r.returncode != 0:
                print(r.stdout[-1500:], r.stderr[-1500:])
                raise SystemExit(f"attack {spec} failed (exit {r.returncode})")
            line = [ln for ln in r.stdout.splitlines() if ln.startswith("{")][-1]
            res = json.loads(line)
            LAST[res.get("name", script)] = res
        return dict(LAST)
    return run


def outcome(res):
    if res["pages_ok"] == 0:
        return "blocked"
    if res["success"] >= 0.95:
        return "full"
    return "partial" if res["success"] < 0.5 else "most"


def expect(name, want, bits=None):
    """A check on one attack's outcome: full / partial / blocked / stopped (at most one product), and its bits."""
    def check(board, results):
        res = LAST.get(name)
        if res is None:
            return False, f"{name} did not run"
        got = outcome(res)
        if want == "stopped" and res["pages_ok"] <= 1:
            got = "stopped"
        if got != want:
            return False, f"{name}: expected {want}, got {got} ({res['pages_ok']}/{res['pages_wanted']}) {res['notes'][-1:]}"
        if bits and not bits(res["bits"]):
            return False, f"{name}: unexpected difficulty {sorted(set(res['bits']))}"
        return True, ""
    return check


def shoppers(board, results):
    """Report only: what the shoppers paid and who gave up (the false-positive column)."""
    personas_ch6.print_pow(results)
    return True, ""


def prices(names):
    def report(board, results):
        print(f"\n{'attack':<30}{'products':>10}{'solves':>8}  {'bits':<10}{'CPU-s per 1,000':>16}{'$ per 1,000':>13}")
        for name in names:
            r = LAST.get(name)
            if not r:
                continue
            bits = ",".join(str(b) for b in sorted(set(r["bits"]))) or "-"
            cpu = f"{r['cpu_s_per_1k']:.2f}" if r["cpu_s_per_1k"] is not None and r["solves"] else "-"
            usd = f"{r['usd_per_1k']:.6f}" if r["usd_per_1k"] is not None and r["solves"] else "-"
            print(f"{name:<30}{r['pages_ok']:>4}/{r['pages_wanted']:<5}{r['solves']:>8}  {bits:<10}{cpu:>16}{usd:>13}")
        print(f"(bot prices assume ${USD_PER_VCPU_HOUR} per vCPU-hour)")
        return True, ""
    return report


def cgnat_pays_more(board, results):
    """The Round 4 false positive: phones sharing a CGNAT address pay the busy neighbours' price."""
    rows = personas_ch6.pow_summary(results).get("mobile_cgnat", {})
    ok = max(rows.get("bits", [0]), default=0) >= 20
    return ok, "no mobile_cgnat shopper paid 20+ bits (the shared-IP false positive did not show up)"


def all_bits(allowed):
    return lambda bits: set(bits) <= set(allowed)


ROUNDS = {
    0: Round(level=0, description="no gate: what does a hash cost? (round0_bench + naive scraper)",
             attack=attack("round0_bench.py", "round1_naive_scraper.py"), scenario="browse",
             extra_checks=[expect("round1_naive_scraper", "full"), shoppers]),
    1: Round(level=1, description="PoW gate with a naive verifier: naive scraper stopped, forged difficulty walks in",
             attack=attack("round1_naive_scraper.py", "round1_forge_difficulty.py"), scenario="browse",
             allowed_fp=("no_js",),
             extra_checks=[expect("round1_naive_scraper", "blocked"), expect("round1_forge_difficulty", "full"),
                           prices(["round1_naive_scraper", "round1_forge_difficulty"]), shoppers],
             solutions=("defenses/ladder.py", "defenses/policy.py")),
    2: Round(level=2, description="signed challenge: forgery stopped, solve once and replay still works",
             attack=attack("round1_forge_difficulty.py", "round2_solve_once_replay.py", "round2_solve_once_replay.py --share"),
             scenario="browse", allowed_fp=("no_js",),
             extra_checks=[expect("round1_forge_difficulty", "blocked"), expect("round2_solve_once_replay", "full"),
                           expect("round2_solve_once_replay_share", "full"),
                           prices(["round1_forge_difficulty", "round2_solve_once_replay", "round2_solve_once_replay_share"]), shoppers],
             solutions=("defenses/ladder.py", "defenses/policy.py")),
    3: Round(level=3, description="single use + pass budget + bound pass: replay and sharing stopped, the solver pool pays",
             attack=attack("round2_solve_once_replay.py", "round2_solve_once_replay.py --share", "round3_solver_pool.py"),
             scenario="browse", allowed_fp=("no_js",),
             extra_checks=[expect("round2_solve_once_replay", "partial"), expect("round2_solve_once_replay_share", "stopped"),
                           expect("round3_solver_pool", "full", bits=all_bits([16])),
                           prices(["round2_solve_once_replay", "round2_solve_once_replay_share", "round3_solver_pool"]), shoppers],
             solutions=("defenses/ladder.py", "defenses/policy.py")),
    4: Round(level=4, description="adaptive difficulty: the pool pays 16-64x, many small clients pay the base price",
             attack=attack("round3_solver_pool.py", "round4_distributed.py"), scenario="browse",
             allowed_fp=("no_js", "mobile_cgnat"),
             extra_checks=[expect("round3_solver_pool", "full", bits=lambda b: max(b) >= 20),
                           expect("round4_distributed", "full", bits=all_bits([16])),
                           prices(["round3_solver_pool", "round4_distributed"]), shoppers, cgnat_pays_more],
             solutions=("defenses/ladder.py", "defenses/policy.py", "defenses/pow_adaptive.py")),
    5: Round(level=4, description="the browser pays: a real Chromium solves with the page's own JavaScript",
             attack=attack("round5_playwright_browser.py"), scenario="browse", allowed_fp=("no_js", "mobile_cgnat"),
             extra_checks=[expect("round5_playwright_browser", "full"), prices(["round5_playwright_browser"]), shoppers],
             solutions=("defenses/ladder.py", "defenses/policy.py")),
}

if __name__ == "__main__":
    main(ROUNDS)
