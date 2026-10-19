"""
Solve-time histogram (Round 4 design aid).

Every answer to the `captcha` challenge is a row in the store's decision log (POST /api/challenge/verify)
with `extra.solve_sim` (simulated seconds from issue to submit), whether it was right, and whether the
submitting IP matched the one that fetched the image. This groups the correct solves by solve time and by
WHO solved them (the scoreboard's ground-truth actor label: human / bot:ocr_retry / bot:farm; the
defenses never see it).

Use the histogram to pick FAST_SOLVE_SIM_S and FARM_BAND_SIM_S in defenses/solver_signals.py. Generate
data first, at level 3:

    python tools/personas_ch5.py                 # the shoppers
    python attacks/round4_retry_ocr.py
    python attacks/round4_solver_farm.py
    python tools/solve_times.py

(`python tools/checkpoint.py --round 4` prints it too.)
"""

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)
import labclient  # noqa: E402

BUCKETS = [0, 1, 2, 3, 5, 8, 10, 15, 20, 30, 40, 60]
MARKS = ["█", "▒", "░", "▓", "·"]


def kind(actor):
    return "human" if actor.startswith("human") else actor


def bucket(t):
    for lo, hi in zip(BUCKETS, BUCKETS[1:]):
        if lo <= t < hi:
            return f"{lo:>2}-{hi:<2} s"
    return f"{BUCKETS[-1]}+ s  "


def rows(limit=5000):
    items = labclient.admin("GET", "/lab/decisions", params={"path": "/api/challenge/verify", "limit": limit})["items"]
    return [d for d in items if "solve_sim" in (d.get("extra") or {})]


def render(items):
    if not items:
        return "No solves logged yet. Run some traffic first (see the docstring)."
    actors = sorted({kind(d["actor"]) for d in items})
    marks = {a: MARKS[i % len(MARKS)] for i, a in enumerate(actors)}
    counts = {}
    for d in items:
        t = d["extra"]["solve_sim"]
        if t >= 0 and d["extra"].get("captcha_correct"):
            row = counts.setdefault(bucket(t), {})
            row[kind(d["actor"])] = row.get(kind(d["actor"]), 0) + 1
    out = ["Correct answers by solve time (simulated seconds)", "", "          " + "   ".join(f"{marks[a]} {a}" for a in actors)]
    for lo, hi in zip(BUCKETS, BUCKETS[1:] + [None]):
        key = f"{lo:>2}-{hi:<2} s" if hi else f"{BUCKETS[-1]}+ s  "
        row = counts.get(key, {})
        bar = "".join(marks[a] * min(40, row.get(a, 0)) for a in actors)
        out.append(f"  {key}  {bar} {' '.join(f'{a}={n}' for a, n in sorted(row.items()))}")
    for a in actors:
        mine = [d for d in items if kind(d["actor"]) == a]
        wrong = sum(d["status"] != 200 for d in mine)
        moved = sum(d["extra"].get("ip_match") is False for d in mine)
        out.append(f"\n  {a:<14} {len(mine)} answers · {wrong} not accepted · {moved} submitted from a different IP than the image was fetched from")
    return "\n".join(out)


if __name__ == "__main__":
    print(render(rows()))
