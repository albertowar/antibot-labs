"""
Chapter 6 — Solve-time scoreboard (Round 4 design aid)

Every CAPTCHA check the demo site makes is logged to the Redis stream
lab:solvelog: who submitted (human / bot / farm, a lab-only label the
defenses never see), whether the answer was right, the solve time in
simulated seconds, and whether the submitting IP matched the issuer.

Use the histogram to pick FAST_SOLVE_SIM_S and FARM_BAND_SIM_S in
defenses/solver_signals.py. Generate data first, at DEFENSE_LEVEL=3:
    python tools/legit_traffic.py
    python attacks/round4_retry_ocr.py
    python attacks/round4_solver_farm.py
Then:
    python tools/scoreboard.py
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from labkit import redis_client  # noqa: E402

BUCKETS = [0, 1, 2, 3, 5, 8, 10, 15, 20, 30, 40, 60]


def bucket(t):
    for lo, hi in zip(BUCKETS, BUCKETS[1:]):
        if lo <= t < hi:
            return f"{lo:>2}–{hi:<2} s"
    return f"{BUCKETS[-1]}+ s  "


def main():
    rows = [fields for _, fields in redis_client().xrange("lab:solvelog")]
    if not rows:
        print("No solves logged yet. Run some traffic first (see the docstring).")
        return
    actors = sorted({r["actor"] for r in rows})
    counts = {}
    for r in rows:
        t = float(r["solve_sim"])
        if t >= 0 and r["ok"] == "1":
            counts.setdefault(bucket(t), {}).setdefault(r["actor"], 0)
            counts[bucket(t)][r["actor"]] += 1
    marks = {"human": "█", "bot": "▒", "farm": "░"}
    print("Correct solves by solve time (simulated seconds)\n")
    print("          " + "   ".join(f"{marks.get(a, '?')} {a}" for a in actors))
    for lo, hi in zip(BUCKETS, BUCKETS[1:] + [None]):
        key = f"{lo:>2}–{hi:<2} s" if hi else f"{BUCKETS[-1]}+ s  "
        row = counts.get(key, {})
        bar = "".join(marks.get(a, "?") * min(40, row.get(a, 0)) for a in actors)
        print(f"  {key}  {bar} {' '.join(f'{a}={n}' for a, n in sorted(row.items()))}")
    for a in actors:
        mine = [r for r in rows if r["actor"] == a]
        wrong = sum(r["ok"] == "0" for r in mine)
        moved = sum(r.get("ip_match") == "0" for r in mine)
        print(f"\n  {a:<6} {len(mine)} checks · {wrong} wrong answers · "
              f"{moved} submitted from a different IP than the issuer")


if __name__ == "__main__":
    main()
