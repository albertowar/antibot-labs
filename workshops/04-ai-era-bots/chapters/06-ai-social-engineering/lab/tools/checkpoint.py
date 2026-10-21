#!/usr/bin/env python3
"""
W4 Ch6 lab: round checkpoints, catch-up and the expected-results table.

    python tools/checkpoint.py --round 1               # judge YOUR out/suspects_r1.csv against Round 1's thresholds
    python tools/checkpoint.py --round 3               # Round 3 judges out/actions_r3.csv
    python tools/checkpoint.py --round 2 --catch-up    # install the reference results for rounds 1..2 as your files (.bak kept)
    python tools/checkpoint.py --restore               # put your own files back
    python tools/checkpoint.py --round 4 --reference   # run the reference detector for a round and judge it
    python tools/checkpoint.py --all --markdown        # every reference round: the README's expected-results table
    python tools/checkpoint.py --all --write-readme    # ...and write it into README.md between the results markers

Your files (each notebook writes its own):
    out/suspects_r1.csv   Round 1  account and profile rules              (members you flag)
    out/suspects_r2.csv   Round 2  Round 1 + conversation shape            (cumulative)
    out/actions_r3.csv    Round 3  payment interventions                   (payment_id,action)
    out/suspects_r4.csv   Round 4  Round 2 + reports, intel, clustering    (cumulative)

A round passes when its tier is caught AND no cohort is over its false-positive budget. The
thresholds are below, in ROUNDS; they are what the reference meets with room to spare, not
what a perfect detector would get.
"""

import argparse
import os
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
LAB = os.path.dirname(HERE)
sys.path.insert(0, HERE)
import score  # noqa: E402

OUT = os.path.join(LAB, "out")
REF = os.path.join(OUT, "reference")
SOL = os.path.join(LAB, "solutions")

ROUNDS = {
    1: {"title": "account and profile rules", "file": "suspects_r1.csv", "solution": "round1_profile.py",
        "min_tier": {"A": 0.80}, "max_flagged_share": 0.05},
    2: {"title": "conversation shape", "file": "suspects_r2.csv", "solution": "round2_shape.py",
        "prev": "suspects_r1.csv", "min_tier": {"A": 0.80, "B": 0.75}, "max_flagged_share": 0.05},
    3: {"title": "interventions at the payment moment", "file": "actions_r3.csv", "solution": "round3_interventions.py",
        "min_prevented": 0.60},
    4: {"title": "reports, partner intel, clustering", "file": "suspects_r4.csv", "solution": "round4_network.py",
        "prev": "suspects_r2.csv", "min_tier": {"A": 0.80, "B": 0.75, "D": 0.75}, "min_recall": 0.85,
        "min_precision_at_25": 0.90, "max_flagged_share": 0.05},
}


def evaluate(n, path, key, prev=None):
    spec = ROUNDS[n]
    fails = []
    if n == 3:
        r = score.score_actions(path, key)
        if r["prevented_share"] < spec["min_prevented"]:
            fails.append(f"scam money prevented {r['prevented_share']:.0%} < {spec['min_prevented']:.0%}")
    else:
        r = score.score_members(path, key, prev)
        for t, lo in spec["min_tier"].items():
            if r["tiers"][t]["recall"] < lo:
                fails.append(f"tier {t} recall {r['tiers'][t]['recall']:.0%} < {lo:.0%}")
        if r["flagged_share"] > spec["max_flagged_share"]:
            fails.append(f"flagged {r['flagged_share']:.1%} of the community > {spec['max_flagged_share']:.0%}")
        if "min_recall" in spec and r["recall"] < spec["min_recall"]:
            fails.append(f"overall recall {r['recall']:.0%} < {spec['min_recall']:.0%}")
        if "min_precision_at_25" in spec and r["precision_at"].get("25", 0) < spec["min_precision_at_25"]:
            fails.append(f"precision@25 {r['precision_at'].get('25', 0):.0%} < {spec['min_precision_at_25']:.0%}")
    if r["cohorts_over_budget"]:
        fails.append("over the false-positive budget: " + ", ".join(r["cohorts_over_budget"]))
    return r, fails


def run_reference(n):
    subprocess.run([sys.executable, os.path.join(SOL, ROUNDS[n]["solution"]), "--no-score"], check=True)
    return os.path.join(REF, ROUNDS[n]["file"])


def judge(n, path, key, prev=None, show=True):
    r, fails = evaluate(n, path, key, prev)
    if show:
        score.print_actions(r) if n == 3 else score.print_members(r, key)
    print(f"\nRound {n} ({ROUNDS[n]['title']}): " + ("PASS" if not fails else "FAIL"))
    for f in fails:
        print(f"  - {f}")
    return not fails, r


def catch_up(n):
    for k in range(1, n + 1):
        src = run_reference(k)
        dst = os.path.join(OUT, ROUNDS[k]["file"])
        if os.path.exists(dst) and not os.path.exists(dst + ".bak"):
            shutil.copy(dst, dst + ".bak")
        shutil.copy(src, dst)
        print(f"catch-up: Round {k} reference -> {os.path.relpath(dst, LAB)}")


def restore():
    n = 0
    for spec in ROUNDS.values():
        dst = os.path.join(OUT, spec["file"])
        if os.path.exists(dst + ".bak"):
            shutil.move(dst + ".bak", dst)
            print(f"restored {os.path.relpath(dst, LAB)}")
            n += 1
    if not n:
        print("nothing to restore")


def markdown(rows):
    lines = ["| Round | You add | Tier A | Tier B | Tier C | Tier D | Flagged | Over budget | Also |",
             "|---|---|---|---|---|---|---|---|---|"]
    for n, r, ok in rows:
        if n == 3:
            t = r["tiers"]
            lines.append(f"| 3 | {ROUNDS[3]['title']} | {t['A']['share']:.0%} | {t['B']['share']:.0%} | "
                         f"{t['C']['share']:.0%} | {t['D']['share']:.0%} | {r['genuine_held']} held, "
                         f"{r['genuine_warned']} warned | {', '.join(r['cohorts_over_budget']) or 'none'} | "
                         f"scam money prevented {r['prevented_share']:.0%} (simulated) |")
            continue
        t = r["tiers"]
        fp = sum(c["flagged"] for c in r["cohorts"].values())
        lines.append(f"| {n} | {ROUNDS[n]['title']} | {t['A']['caught']}/{t['A']['total']} | {t['B']['caught']}/{t['B']['total']} | "
                     f"{t['C']['caught']}/{t['C']['total']} | {t['D']['caught']}/{t['D']['total']} | "
                     f"{r['flagged']} ({fp} genuine) | {', '.join(r['cohorts_over_budget']) or 'none'} | "
                     f"precision@25 {r['precision_at'].get('25', 0):.0%} |")
    lines.append("")
    lines.append("Round 3's tier columns are the share of each tier's scam money a hold or warning stopped. "
                 "The genuine members each round touched, against their cohort's budget (the honest cost):")
    lines.append("")
    for n, r, ok in rows:
        if n == 3:
            hit = [f"{k} {c['held']} held of {c['hold_budget']}" for k, c in r["genuine"].items() if c["held"]]
            hit += [f"{k} {c['warned']} warned of {c['warn_budget']}" for k, c in r["genuine"].items() if c["warned"]]
        else:
            hit = [f"{k} {c['flagged']} of {c['budget']}" for k, c in r["cohorts"].items() if c["flagged"]]
        lines.append(f"- Round {n}: " + ("; ".join(hit) if hit else "none"))
    return "\n".join(lines)


def write_readme(table):
    path = os.path.join(LAB, "README.md")
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    a, b = "<!-- results:start -->", "<!-- results:end -->"
    if a not in text or b not in text:
        raise SystemExit("README.md has no results markers")
    head, rest = text.split(a, 1)
    _, tail = rest.split(b, 1)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(head + a + "\n" + table + "\n" + b + tail)
    print("README.md: expected-results table rewritten")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--round", type=int, choices=sorted(ROUNDS))
    ap.add_argument("--catch-up", action="store_true", help="install the reference results for rounds 1..N as your files")
    ap.add_argument("--reference", action="store_true", help="judge the reference detector instead of your file")
    ap.add_argument("--restore", action="store_true")
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--markdown", action="store_true")
    ap.add_argument("--write-readme", action="store_true")
    args = ap.parse_args()
    key = score.load_key()
    if score.data_digest() != key["sha256"]:
        print("WARNING: data/ does not match the answer key; re-run  python tools/make_trailmates.py", file=sys.stderr)
    if args.restore:
        return restore()
    if args.all:
        rows, ok_all = [], True
        for n in sorted(ROUNDS):
            path = run_reference(n)
            prev = os.path.join(REF, ROUNDS[n]["prev"]) if "prev" in ROUNDS[n] else None
            ok, r = judge(n, path, key, prev, show=not (args.markdown or args.write_readme))
            rows.append((n, r, ok))
            ok_all &= ok
        if args.markdown or args.write_readme:
            table = markdown(rows)
            print("\n" + table)
            if args.write_readme:
                write_readme(table)
        return 0 if ok_all else 1
    if not args.round:
        ap.print_help()
        return 0
    n = args.round
    if args.catch_up:
        catch_up(n)
    if args.reference:
        path = run_reference(n)
        prev = os.path.join(REF, ROUNDS[n]["prev"]) if "prev" in ROUNDS[n] else None
    else:
        path = os.path.join(OUT, ROUNDS[n]["file"])
        prev = os.path.join(OUT, ROUNDS[n]["prev"]) if "prev" in ROUNDS[n] else None
        if not os.path.exists(path):
            print(f"{os.path.relpath(path, LAB)} does not exist yet: run notebook 0{n} (or --catch-up to start from the reference)")
            return 1
    if prev and not os.path.exists(prev):
        prev = None
    ok, _ = judge(n, path, key, prev)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
