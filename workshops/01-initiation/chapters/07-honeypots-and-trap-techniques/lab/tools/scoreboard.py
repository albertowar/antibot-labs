"""
Chapter 7 — Scoreboard (Section 7.5)

What the SERVER recorded for every actor since the last reset. Compare it with
what each bot printed: at level 1+ a bot "succeeds" at signups the server
silently dropped.

Columns:
  req      requests that went through the trap checks
  signups  created / trapped (dropped) / quarantined
  403      requests blocked (level 4, RESPONSE_MODE=block)
  reviews  published / suppressed or dropped
  traps    trap hits by type

Run:
    python tools/scoreboard.py
    curl -X POST http://localhost:5000/lab/reset     # start a fresh count
"""

import json
import os
import statistics
import sys
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "attacks"))

from _lab import BASE_URL, require_local  # noqa: E402

SHORT = {"honeypot_field": "honeypot", "timing_token_missing": "no-token", "too_fast": "too-fast",
         "trap_link": "link", "honey_record": "honey", "decoy_endpoint": "decoy"}


def fetch_summary():
    require_local()
    with urllib.request.urlopen(f"{BASE_URL}/lab/summary", timeout=5) as resp:
        return json.loads(resp.read())


def trap_hits(counters):
    return {k[5:]: v for k, v in counters.items() if k.startswith("trap:")}


def row(actor, c):
    traps = ", ".join(f"{SHORT.get(k, k)}×{v}" for k, v in sorted(trap_hits(c).items())) or "–"
    signups = (f"{c.get('signup_created', 0)}/{c.get('signup_trapped', 0)}/"
               f"{c.get('signup_quarantined', 0)}") if c.get("signup_attempts") else "–"
    reviews = (f"{c.get('review_published', 0)}/"
               f"{c.get('review_suppressed', 0) + c.get('review_dropped', 0)}")
    return (f"  {actor:<24} {c.get('requests', 0):>4}  {signups:>8}  {c.get('blocked', 0):>4}  "
            f"{reviews:>7}  {traps}")


def cost_line(timings):
    if len(timings) < 2:
        return "  trap checks: not enough requests yet"
    p95 = statistics.quantiles(timings, n=20)[-1]
    return (f"  trap checks: median {statistics.median(timings):.3f} ms, p95 {p95:.3f} ms "
            f"per request ({len(timings)} requests)")


def print_scoreboard(summary):
    print(f"  {'actor':<24} {'req':>4}  {'signups':>8}  {'403':>4}  {'reviews':>7}  traps")
    for actor, counters in sorted(summary["actors"].items()):
        print(row(actor, counters))
    print("\nDefender cost")
    print(cost_line(summary["timings_ms"]))


if __name__ == "__main__":
    print("=== Scoreboard (server's view since the last reset) ===")
    print_scoreboard(fetch_summary())
