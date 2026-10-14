"""
Round checkpoint for Chapter 9 (the Drop). Declares the rounds and hands over to checkpoint_core.

Every round is a drop: restock to 20 hoodies, release the 40 shoppers (tools/personas_ch9.py) and one
scalper wave at the same moment, then read the SERVER's count (a trapped bot is told it bought, so its own
number is what it believes). A round runs two waves, each in its own drop: the wave this round must STOP
and the wave that BEATS this round (the reason the next round exists). Each also checks which shoppers a
defense stopped: only the personas the round names may be hurt, anything else is a false positive.

    python tools/checkpoint.py --round 3              # set level 3, run waves 2 and 3
    python tools/checkpoint.py --round 3 --level 2    # the same waves against Round 2's defenses (the "before")
    python tools/checkpoint.py --round 3 --catch-up   # a no-op here: the defenses are pre-written
    python tools/checkpoint.py --restore              # puts back any .bak a lab edit left (none in this lab)
    python tools/checkpoint.py --all --markdown       # every round, key waves only
    python tools/checkpoint.py --all --full --markdown   # every round against EVERY wave up to the next one:
                                                         # the wave-by-round matrix in the README (slow)

Waves 3 and 4 drive Chromium (`pip install -r requirements-browser.txt`, `python -m playwright install
chromium`). `--skip-browser` leaves them out of a round (their expectations are skipped too). Under
tools/verify.py, which has its own flags, use the environment: CHECKPOINT_FULL=1, CHECKPOINT_SKIP_BROWSER=1.
"""

import atexit
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import drop  # noqa: E402
import personas_ch9  # noqa: E402
import population  # noqa: E402
from checkpoint_core import Round, main  # noqa: E402

# Two switches checkpoint_core's argparse does not know. As flags here, as environment variables under
# tools/verify.py (CHECKPOINT_FULL=1, CHECKPOINT_SKIP_BROWSER=1).
FULL = "--full" in sys.argv or os.environ.get("CHECKPOINT_FULL") == "1"
SKIP_BROWSER = "--skip-browser" in sys.argv or os.environ.get("CHECKPOINT_SKIP_BROWSER") == "1"
sys.argv = [a for a in sys.argv if a not in ("--full", "--skip-browser")]

# Bot share of the 20 hoodies that counts as each expectation.
# "capped": wave 3 mints 6 sessions, and from Round 4 each one may buy at most one hoodie
EXPECT = {
    "wins": (lambda n: n >= 10, "takes >= 10 of 20"),
    "stopped": (lambda n: n <= 4, "gets <= 4 of 20"),
    "capped": (lambda n: n <= 6, "gets <= 6 of 20 (one per minted session)"),
    "some": (lambda n: n >= 1, "still gets a few"),
}
RESULTS = {}        # (round, wave) -> the drop's numbers, for the matrix
DROPS = {}          # wave -> the last full drop result (checkpoint_core only keeps the small dict below)


def wave_attack(n):
    """An attack for checkpoint_core: one full drop against wave n, judged by the server's count."""
    def run():
        result = drop.run_drop([n])
        DROPS[n] = result
        hurt = drop.hurt_personas(result)
        slow = personas_ch9.slowed(result["humans"])
        return {"attempted": drop.STOCK, "succeeded": drop.bot_sold(result, n), "believed": result["bots"][n].get("believed"),
                "humans_bought": result["sold"].get("humans", 0), "hurt": hurt, "slowed": len(slow),
                "gate_ms_median": result["gate_ms"]["median"]}
    return run


def expect(n, wave, want, allowed):
    """extra_check: wave `wave` meets `want` in round n, and no shopper outside `allowed` was hurt."""
    def check(board, results, attacks):
        out = attacks.get(f"wave{wave}")
        if out is None:
            return True, ""                                   # skipped (--skip-browser)
        RESULTS[(n, wave)] = out
        drop.print_scoreboard(DROPS[wave])
        ok_fn, text = EXPECT[want]
        problems = []
        if not ok_fn(out["succeeded"]):
            problems.append(f"wave {wave} should be {want} ({text}): the store sold it {out['succeeded']}")
        extra = sorted(set(out["hurt"]) - set(allowed))
        if extra:
            problems.append(f"wave {wave} drop: shoppers stopped who should not be: {', '.join(extra)}")
        return not problems, "; ".join(problems)
    return check


def noop(p, client, rng):
    p.result.update(outcome="browsed")


def waves_for(level, key, allowed, extra_waves=()):
    """
    The pieces of a Round that run waves: the attacks, the checks that judge them, the shoppers' scenario.
    key: {wave: expectation} for the judged waves; extra_waves run too under --full (shown, not judged).
    """
    waves = dict(key)
    if FULL:
        for w in extra_waves:
            waves.setdefault(w, None)
    if SKIP_BROWSER:
        waves = {w: e for w, e in waves.items() if w not in drop.BROWSER_WAVES}
    return dict(attacks={f"wave{w}": wave_attack(w) for w in sorted(waves)},
                extra_checks=[expect(level, w, e, allowed) if e else _show(level, w) for w, e in sorted(waves.items())],
                scenario=noop, population_n=1)


def _show(n, wave):
    def check(board, results, attacks):
        out = attacks[f"wave{wave}"]
        RESULTS[(n, wave)] = out
        drop.print_scoreboard(DROPS[wave])
        return True, ""
    return check


def all_before(n):
    return range(0, min(n + 1, 4) + 1)


ROUNDS = {
    0: Round(level=0, description="baseline: no defenses, the naive scalper takes the drop",
             **waves_for(0, {0: "wins"}, (), all_before(0))),
    1: Round(level=1, description="rate limits + headers: the naive scalper stopped, the cloud fleet walks in",
             **waves_for(1, {0: "stopped", 1: "wins"}, (), all_before(1))),
    2: Round(level=2, description="IP reputation: the fleet stopped (and the VPN shoppers with it), residential proxies walk in",
             **waves_for(2, {1: "stopped", 2: "wins"}, ("consumer_vpn",), all_before(2))),
    3: Round(level=3, description="session guard + traps: the filler is trapped, minted sessions walk in",
             **waves_for(3, {2: "stopped", 3: "wins"}, ("consumer_vpn",), all_before(3))),
    4: Round(level=4, description="proof of work + binding + one per customer: minted sessions capped, a browser per hoodie still buys",
             **waves_for(4, {3: "capped", 4: "some"}, ("no_js",), all_before(4))),
}


def matrix():
    """The wave-by-round table the README prints (only with --full)."""
    if not RESULTS:
        return
    waves = sorted({w for _, w in RESULTS})
    rounds = sorted({r for r, _ in RESULTS})
    print("\n| Wave / end of round | " + " | ".join(str(r) for r in rounds) + " |")
    print("|---|" + "---|" * len(rounds))
    for w in waves:
        cells = [str(RESULTS[(r, w)]["succeeded"]) if (r, w) in RESULTS else "-" for r in rounds]
        print(f"| wave {w} ({drop.WAVES[w][1].split(':')[1]}) | " + " | ".join(cells) + " |")
    for label, f in (("Shoppers stopped", lambda o: ",".join(o["hurt"]) or "0"), ("Shoppers slowed >= 1 s", lambda o: str(o["slowed"]))):
        cells = []
        for r in rounds:
            seen = [f(RESULTS[(r, w)]) for w in waves if (r, w) in RESULTS]
            cells.append(" / ".join(dict.fromkeys(seen)) if seen else "-")
        print(f"| {label} | " + " | ".join(cells) + " |")


if "--markdown" in sys.argv:                # also when imported by tools/verify.py
    atexit.register(matrix)

if __name__ == "__main__":
    main(ROUNDS)
