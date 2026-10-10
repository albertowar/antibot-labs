"""
Chapter 7 — Scoreboard: both sides of every round

A detection rate on its own is half a result. Every checkpoint prints:

  Bot traffic        checkout success per attack (lower is better)
  Real users         blocked per cohort (lower is better; this is the cost)
  Defender cost      scoring latency at checkout (Server-Timing: mlscore)
  Attacker cost      simulated proxy + fingerprint spend per successful checkout

Ground truth (who is a bot) comes from the simulators. This is the one
place in the lab allowed to use it.
"""

import statistics
from collections import defaultdict

import shopper


def pct(n, d):
    return f"{n}/{d} ({n / d:.0%})" if d else "–"


def latency(results):
    ms = sorted(r["score_ms"] for r in results if r["score_ms"] is not None)
    if not ms:
        return None
    return statistics.median(ms), ms[min(len(ms) - 1, int(len(ms) * 0.95))]


def summarize(results):
    """{actor: (successes, total, usd)} for bots; {cohort: (blocked, total)} for humans."""
    bots, humans, errors = defaultdict(lambda: [0, 0, 0.0]), defaultdict(lambda: [0, 0]), 0
    for r in results:
        if str(r["final"]).startswith("error"):
            errors += 1
            continue
        if r["is_bot"]:
            b = bots[r["actor"]]
            b[0] += shopper.succeeded(r)
            b[1] += 1
            b[2] += r["usd"] + r["config"].get("extra_usd", 0)
        else:
            h = humans[r["cohort"]]
            h[0] += not shopper.succeeded(r)
            h[1] += 1
    return bots, humans, errors


def report(results, bot_expect=None, human_budget=None, extra_bot_usd=None):
    """Print the scoreboard. Returns the number of expectations that failed."""
    bot_expect = bot_expect or {}
    extra_bot_usd = extra_bot_usd or {}
    bots, humans, errors = summarize(results)
    failures = 0

    print("Bot traffic                         checkouts succeeded")
    for actor, (ok, n, usd) in sorted(bots.items()):
        mark, note = "  ", ""
        if actor in bot_expect:
            lo, hi, label = bot_expect[actor]
            good = lo <= ok / n <= hi
            failures += not good
            mark, note = ("✅" if good else "❌"), f"expected: {label}"
        print(f"  {mark} {actor:<28} {pct(ok, n):<14} {note}")

    print("\nReal users (simulated cohorts)      blocked or cancelled")
    total_blocked = total = 0
    for cohort, (blocked, n) in sorted(humans.items()):
        total_blocked += blocked
        total += n
        print(f"     {cohort:<28} {pct(blocked, n)}")
    if total:
        line = f"total {pct(total_blocked, total)}"
        if human_budget is not None:
            good = total_blocked / total <= human_budget
            failures += not good
            line = f"{'✅' if good else '❌'} {line}   (budget ≤ {human_budget:.0%})"
        print(f"  {line}")

    print("\nDefender cost")
    lat = latency(results)
    print(f"  ML scoring: median {lat[0]:.1f} ms, p95 {lat[1]:.1f} ms per checkout"
          if lat else "  ML scoring: not running (DEFENSE_LEVEL=0)")

    print("\nAttacker cost (simulated)")
    for actor, (ok, n, usd) in sorted(bots.items()):
        usd += extra_bot_usd.get(actor, 0.0)
        per = f"${usd / ok:.2f} per successful checkout" if ok else "no successful checkout"
        print(f"  {actor:<28} ${usd:>7.2f} total · {per}")
    if errors:
        print(f"\n⚠️  {errors} sessions failed with transport errors (server overloaded or restarted?)")
    return failures
