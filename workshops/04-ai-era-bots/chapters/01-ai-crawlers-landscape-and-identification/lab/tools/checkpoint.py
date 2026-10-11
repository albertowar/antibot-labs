"""Round checkpoint: measure both sides, pass or fail, and catch up if you fell behind.

    python tools/checkpoint.py --round N              # test your defenses at DEFENSE_LEVEL=N
    python tools/checkpoint.py --round N --catch-up   # install the reference solutions for rounds 1..N

For round N it (1) checks the store runs at DEFENSE_LEVEL=N, (2) resets the store and
runs the legitimate cohort, (3) resets again and runs every attack up to round N, then
prints what each side achieved and a verdict:

  PASS when no person and no verified crawler is blocked or challenged, and every
  attack from earlier rounds stays under its ceiling. The current round's attack is
  shown but not judged: it is supposed to get through. That is the next round.

Catch-up copies solutions/round{1..N}/ over defenses/ (and Round 1's robots.txt over
demo_site/robots.txt), keeping each of your files once as .bak (--restore puts them back).
The store reloads defense files on the fly; only DEFENSE_LEVEL needs a restart.
"""

from __future__ import annotations

import argparse
import importlib
import os
import shutil
import statistics
import sys
import time

import requests

HERE = os.path.dirname(os.path.abspath(__file__))
LAB_DIR = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(LAB_DIR, "attacks"))
sys.path.insert(0, HERE)
from _common import BASE_URL, require_local  # noqa: E402
import legit_traffic  # noqa: E402

ATTACKS = {
    0: ("round0_declared_crawler", {}, "round0 declared GPTBot (honours robots.txt)"),
    1: ("round1_impersonate_searchbot", {}, "round1 impersonated OAI-SearchBot"),
    2: ("round2_stealth_chrome", {}, "round2 stealth Chrome, 4 cloud IPs"),
    3: ("round3_polite_distributed", {}, "round3 polite crawler, 30 ISP IPs"),
}
# level -> {attack round: max coverage % that counts as stopped; None = shown, not judged}
EXPECT = {
    0: {0: None},
    1: {0: 0, 1: None},
    2: {0: 0, 1: 0, 2: None},
    3: {0: 0, 1: 0, 2: 15, 3: 60},
    4: {0: 0, 1: 0, 2: 15, 3: 60},
}
SOLUTION_FILES = {1: ["crawler_registry.py"], 2: ["crawler_verify.py"],
                  3: ["crawl_signature.py"], 4: ["policy.py"]}


sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))  # lab root: labnet.py
import labnet  # noqa: E402


def catch_up(upto):
    """Install the reference solutions for rounds 1..upto (each of your files is kept once as .bak)."""
    installed = labnet.catch_up(LAB_DIR, upto)
    for f in installed:
        print(f"  installed solutions -> {f}   (your version kept as {f}.bak; --restore puts it back)")
    if not installed:
        print("  nothing to install up to this round")
    print(f"[catch-up] make sure the store runs at DEFENSE_LEVEL={upto}: DEFENSE_LEVEL={upto} python demo_site/app.py")


def reset(base):
    requests.post(f"{base}/lab/reset", timeout=5)


def latency(base):
    rows = requests.get(f"{base}/lab/decisions", timeout=10).json()
    lat = sorted(r["latency_ms"] for r in rows)
    if not lat:
        return None
    return statistics.median(lat), lat[int(0.95 * (len(lat) - 1))]


def run(round_: int, base: str = BASE_URL) -> bool:
    require_local(base)
    try:
        status = requests.get(f"{base}/admin/status", timeout=3).json()
    except Exception:
        raise SystemExit(f"Demo store not reachable at {base}. Start it: DEFENSE_LEVEL={round_} python demo_site/app.py")
    if status["level"] != round_:
        print(f"❌ The store runs at DEFENSE_LEVEL={status['level']}, this checkpoint needs {round_}.\n"
              f"   Restart it: DEFENSE_LEVEL={round_} python demo_site/app.py")
        return False

    print(f"\n=== Round {round_} checkpoint (store at DEFENSE_LEVEL={round_}) ===")
    failures, warnings = [], []

    # 1. Legitimate traffic on a clean store.
    reset(base)
    results = legit_traffic.run(base)
    print("\nLegitimate traffic (14 personas)")
    for group, label in (("humans", "humans"), ("non-browser", "non-browser legit"), ("crawlers", "declared crawlers")):
        rows = [r for r in results if r["group"] == group]
        for r in rows:
            t = r["tally"]
            hurt = t["block"] + t["challenge"]
            name = r["name"]
            if name == "localsearchbot":
                if round_ == 3 and hurt:
                    warnings.append(f"localsearchbot refused after {t['allow']} page(s): unverifiable + crawler behaviour. "
                                    f"The documented Round 3 false positive; Round 4 turns it into a budget.")
                    print(f"  ⚠️ {name:<24} blocked {t['block']}  served {t['allow']}   <- documented false positive at L3")
                    continue
                if hurt:
                    failures.append(f"{name} was refused ({t['block']} blocked, {t['challenge']} challenged): "
                                    f"'we cannot verify it' is not 'it is lying'. Limit it, do not block it.")
                extra = f"  ⚠️ {t['limit']} limited (budget)" if t["limit"] else ""
                print(f"  {'❌' if hurt else '✅'} {name:<24} served {t['allow']}/{sum(t.values())}{extra}")
                continue
            if hurt:
                who = "person" if group == "humans" else ("legitimate client" if group == "non-browser" else "verified crawler")
                failures.append(f"{name} ({who}) refused: {t['block']} blocked, {t['challenge']} challenged")
            if t["limit"]:
                warnings.append(f"{name} rate-limited {t['limit']}x (friction)")
            extra = ""
            if r.get("skipped"):
                extra = f"  (robots.txt: skipped {r['skipped']} product URLs voluntarily)"
            if t["limit"]:
                extra += f"  ⚠️ {t['limit']} limited"
            print(f"  {'❌' if hurt else '✅'} {name:<24} served {t['allow']}/{sum(t.values())}{extra}")

    # 2. Attacks, each on a clean store.
    print(f"\nAttacks (coverage of the product catalog)")
    for rd, ceiling in EXPECT[round_].items():
        reset(base)
        mod_name, kwargs, label = ATTACKS[rd]
        mod = importlib.import_module(mod_name)
        importlib.reload(mod)
        res = mod.run(base=base, **kwargs)
        cov = res["coverage"]
        if ceiling is None:
            mark, note = "⚠️", "gets through: that is the next round"
            if rd == 3:
                mark, note = "⚠️", "the residual (try --cookies)"
        elif cov <= ceiling:
            mark, note = "✅", f"ceiling {ceiling}%"
        else:
            mark, note = "❌", f"over the ceiling of {ceiling}%"
            failures.append(f"{label}: {cov:.0f}% coverage, ceiling {ceiling}%")
        print(f"  {mark} {label:<44} {cov:5.0f}%   {note}")

    lat = latency(base)
    if lat:
        print(f"\nDefender cost\n  identification: median {lat[0]:.2f} ms, p95 {lat[1]:.2f} ms per page request")

    for w in warnings:
        print(f"\n⚠️  {w}")
    if failures:
        print(f"\n❌ Round {round_} checkpoint failed:")
        for f in failures:
            print(f"   - {f}")
        return False
    print(f"\n✅ Round {round_} checkpoint passed.")
    return True


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--round", type=int, choices=[0, 1, 2, 3, 4], required="--restore" not in sys.argv)
    ap.add_argument("--catch-up", action="store_true")
    ap.add_argument("--restore", action="store_true", help="put your .bak files back, then exit")
    ap.add_argument("--url", default=BASE_URL)
    a = ap.parse_args()
    if a.restore:
        restored = labnet.restore(LAB_DIR)
        print("restored: " + (", ".join(restored) or "nothing to restore (no .bak files)"))
        sys.exit(0)
    if a.catch_up:
        catch_up(a.round)
        sys.exit(0)
    sys.exit(0 if run(a.round, a.url) else 1)
