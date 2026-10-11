"""Round checkpoint — run at the end of every round, measuring BOTH sides.

For the chosen round it resets the store, runs the legitimate cohorts, then
resets again and runs that round's crawlers, so each side is measured on a
clean slate. It prints:

    legit:   per cohort, how the real users and the verified search crawler fared
    bots:    each crawler's catalogue coverage, requests, maze pages and spend
    cost:    what the defense cost the defender (maze generation, bytes, cap hits)
    verdict: PASS when the round's crawler is held under its ceiling AND no
             legitimate request was blocked, paywalled, charged or mazed

Rounds are cumulative. The store must be running at DEFENSE_LEVEL=N for round
N, and the earlier rounds' modules must be done (or caught up).

Fell behind, or want to see the finished defense?
    python tools/checkpoint.py --round 3 --catch-up   # installs rounds 1..3 reference solutions
    python tools/checkpoint.py --restore                # put your own files back (.bak)

Run with the demo store already running (DEFENSE_LEVEL=N python demo_site/app.py).
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
from _common import BASE_URL, require_local  # noqa: E402
import legit_traffic  # noqa: E402

MODULES = {1: "crawl_policy", 2: "enforce", 3: "maze", 4: "paywall"}


sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))  # lab root: labnet.py
import labnet  # noqa: E402


def manage_solutions(round_, catch_up):
    """--catch-up installs the reference solutions for rounds 1..round_ (your files are kept as .bak).
    Without it the checkpoint tests whatever is in defenses/; --restore puts your .bak files back."""
    if not catch_up:
        return
    for f in labnet.catch_up(LAB_DIR, round_):
        print(f"[catch-up] installed solutions -> {f}   (your version kept as {f}.bak)")


def reset(base):
    httpx.post(f"{base}/lab/reset", timeout=5)


def decisions(base, level):
    return httpx.get(f"{base}/lab/decisions", params={"level": level}, timeout=10).json()


def coverage(rows, actor="bot"):
    skus = set()
    for r in rows:
        if r["actor"] == actor and r["outcome"] in ("allow", "charged") and r["skus"]:
            skus.update(r["skus"].split(","))
    return len(skus) / 300


def run_attack(name, base, **kw):
    mod = importlib.reload(importlib.import_module(name))
    return mod.run(base=base, **kw)


def run(round_, catch_up=False, base=BASE_URL):
    require_local(base)
    try:
        who = httpx.get(f"{base}/whoami", timeout=3).json()
    except Exception:
        raise SystemExit(f"Demo store not reachable at {base}. Start it: DEFENSE_LEVEL={round_} python demo_site/app.py")
    if who["level"] != round_:
        raise SystemExit(f"Store is at DEFENSE_LEVEL={who['level']}, round {round_} needs {round_}. Restart it.")
    manage_solutions(round_, catch_up)

    reset(base)
    legit = legit_traffic.run_legit(base)
    hurt = legit_traffic.hurt(legit)
    reset(base)

    print(f"\n=== Round {round_} checkpoint ===")
    for name, t in legit.items():
        print(f"  legit {name:9s} {dict(t)}")

    checks = []
    if round_ == 1:
        comp = run_attack("round1_compliant_crawler", base)
        rows = decisions(base, 1)
        viol_comp = sum(1 for r in rows if r["actor"] == "bot" and "robots-violation" in r["reason"])
        reset(base)
        ign = run_attack("round1_ignoring_crawler", base)
        rows = decisions(base, 1)
        viol_ign = sum(1 for r in rows if r["actor"] == "bot" and "robots-violation" in r["reason"])
        robots = httpx.get(f"{base}/robots.txt", timeout=5).text
        hdrs = httpx.get(f"{base}/", timeout=5).headers
        checks += [("compliant crawler coverage 0%", comp["coverage"] == 0),
                   ("compliant crawler committed 0 robots violations", viol_comp == 0),
                   ("robots.txt has a LabTrainBot group with Disallow: /",
                    "User-agent: LabTrainBot\nDisallow: /" in robots),
                   ("robots.txt carries Content-Signal, Content-Usage and License lines",
                    all(k in robots for k in ("Content-Signal:", "Content-Usage:", "License:"))),
                   ("pages carry Content-Usage + Link rel=license headers",
                    "Content-Usage" in hdrs and 'rel="license"' in hdrs.get("Link", "")),
                   (f"ignoring crawler got {ign['coverage']:.0%} and logged {viol_ign} violations (expected: all, >0)",
                    viol_ign > 0)]
        bots = {"compliant": comp, "ignoring": ign}
    elif round_ == 2:
        ign = run_attack("round1_ignoring_crawler", base)
        reset(base)
        stealth = run_attack("round2_stealth_crawler", base)
        checks += [("ignoring (unverified) LabTrainBot coverage <= 2%", ign["coverage"] <= 0.02),
                   (f"stealth crawler got {stealth['coverage']:.0%} (expected: all; that is the lesson)", True)]
        bots = {"ignoring": ign, "stealth": stealth}
    elif round_ == 3:
        naive = run_attack("round3_stealth_crawler", base)
        stats = httpx.get(f"{base}/lab/stats", timeout=5).json()["maze"]
        reset(base)
        aware = run_attack("round3_maze_aware_crawler", base)
        maze_share = naive["maze_pages"] / max(1, naive["requests"])
        checks += [("naive stealth crawler coverage <= 15%", naive["coverage"] <= 0.15),
                   (f"naive crawler spent >= 70% of its budget in the maze ({maze_share:.0%})", maze_share >= 0.70),
                   (f"maze-aware crawler got {aware['coverage']:.0%} (expected: all; the rung's limit)", True)]
        pages = max(1, stats["pages"])
        print(f"  cost  maze: {stats['pages']} decoy pages, {stats['gen_ms_total'] / pages:.2f} ms/page to generate, "
              f"{stats['bytes'] / 1024:.0f} KB served, concurrency cap hit {stats['capped']}x")
        bots = {"naive": naive, "aware": aware}
    else:
        paying = run_attack("round4_paying_crawler", base)
        ledger = httpx.get(f"{base}/lab/stats", timeout=5).json()["ledger"]
        reset(base)
        leak = run_attack("round4_free_path_leak", base)
        ledger_total = round(ledger.get("total", 0.0), 2)
        checks += [("paying crawler coverage 100%", paying["coverage"] >= 0.99),
                   (f"ledger ${ledger_total:.2f} == crawler's bill ${paying['spent_usd']:.2f}",
                    abs(ledger_total - paying["spent_usd"]) < 0.005 and ledger_total > 0),
                   ("free-path leak coverage <= 5%", leak["coverage"] <= 0.05)]
        print(f"  cost  ledger: {ledger}")
        bots = {"paying": paying, "leak": leak}

    checks.append(("0 legitimate requests blocked / paywalled / charged / mazed", hurt == 0))
    for b, rep in bots.items():
        print(f"  bots  {b:9s} coverage {rep['coverage']:.0%}  requests {rep['requests']}  "
              f"maze {rep['maze_pages']}  spent ${rep['spent_usd']:.2f}")
    passed = all(ok for _, ok in checks)
    for label, ok in checks:
        print(f"  {'✅' if ok else '❌'} {label}")
    print(f"  verdict: {'PASS' if passed else 'FAIL'}")
    if hurt:
        print(f"    - {hurt} legitimate requests hurt: your rule is too broad (false positives)")
    return passed


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--round", type=int, choices=[1, 2, 3, 4], required="--restore" not in sys.argv)
    ap.add_argument("--catch-up", action="store_true")
    ap.add_argument("--restore", action="store_true", help="put your .bak files back, then exit")
    ap.add_argument("--url", default=BASE_URL)
    a = ap.parse_args()
    if a.restore:
        restored = labnet.restore(LAB_DIR)
        print("restored: " + (", ".join(restored) or "nothing to restore (no .bak files)"))
        sys.exit(0)
    sys.exit(0 if run(a.round, catch_up=a.catch_up, base=a.url) else 1)
