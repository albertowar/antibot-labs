"""
Regression tests for the generator and the tiering claims.

    python tests/test_make_log.py            # golden digest at --scale 0.05 (fast, stdlib only)
    python tests/test_make_log.py --tiers    # run the three reference detectors on the full data and assert the tier bounds

The golden digest pins determinism across Python versions. The tier test is the
promise the chapter makes: rules catch tier A and little else, the graph adds tier
B, the model adds tier C, and no legitimate cohort goes over budget at the
reference operating points. If you change the generator, re-run both and update
GOLDEN and the README's expected-results table from the output.
"""

import hashlib
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
LAB = os.path.dirname(HERE)
GOLDEN_FILE = os.path.join(HERE, "golden.json")


def golden_digest():
    sys.path.insert(0, os.path.join(LAB, "tools"))
    import make_log
    w, accounts, cohorts, key, rows, seq_to_id = make_log.generate(seed=2026, scale=0.05)
    h = hashlib.sha256()
    for row in rows:
        h.update((json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n").encode())
    return h.hexdigest(), len(rows)


def test_golden(update=False):
    digest, n = golden_digest()
    if update or not os.path.exists(GOLDEN_FILE):
        with open(GOLDEN_FILE, "w") as f:
            json.dump({"scale": 0.05, "seed": 2026, "sha256": digest, "events": n}, f, indent=1)
        print(f"golden written: {digest} ({n} events)")
        return
    with open(GOLDEN_FILE) as f:
        g = json.load(f)
    assert g["sha256"] == digest, f"digest drift: {digest} != golden {g['sha256']} (python {sys.version.split()[0]})"
    print(f"golden ok: {digest} ({n} events, python {sys.version.split()[0]})")


def test_tiers():
    ck = os.path.join(LAB, "solutions", "checkpoints")
    reports = {}
    for n, script in ((1, "round1_rules.py"), (2, "round2_graph.py"), (3, "round3_anomaly.py")):
        subprocess.run([sys.executable, os.path.join(LAB, "solutions", script), "--no-score"], check=True, stdout=subprocess.DEVNULL)
        out = os.path.join(tempfile.gettempdir(), f"ch7_r{n}.json")
        subprocess.run([sys.executable, os.path.join(LAB, "tools", "score.py"), os.path.join(ck, f"suspects_r{n}.csv"), "--json", out, "--no-hash"], check=True, stdout=subprocess.DEVNULL)
        with open(out) as f:
            reports[n] = json.load(f)

    def recall(r, tier):
        t = r["tiers"][tier]
        return t["caught"] / t["total"]
    r1, r2, r3 = reports[1], reports[2], reports[3]
    checks = [
        ("R1 tier A recall >= 0.80", recall(r1, "A") >= 0.80),
        ("R1 tier B recall <= 0.25", recall(r1, "B") <= 0.25),
        ("R1 tier C recall <= 0.10", recall(r1, "C") <= 0.10),
        ("R2 tier B recall >= 0.75", recall(r2, "B") >= 0.75),
        ("R2 tier C recall <= 0.15", recall(r2, "C") <= 0.15),
        ("R3 tier C recall in [0.45, 0.75]", 0.45 <= recall(r3, "C") <= 0.75),
        ("R3 precision@100 >= 0.25", r3["queue"]["100"]["precision"] >= 0.25),
    ]
    # Rounds 1 and 2 produce block-grade findings and must respect the cohort budget.
    # Round 3 produces a review queue: a queue entry is friction, not an action, so it is judged on precision.
    for n in (1, 2):
        over = [c["cohort"] for c in reports[n]["cohorts"] if not c["ok"]]
        checks.append((f"R{n} no cohort over budget (over: {over})", not over))
    failed = [name for name, ok in checks if not ok]
    for name, ok in checks:
        print(("ok   " if ok else "FAIL ") + name)
    print("tiers: " + "  ".join(f"R{n}: A {r['tiers']['A']['caught']}/{r['tiers']['A']['total']} B {r['tiers']['B']['caught']}/{r['tiers']['B']['total']} C {r['tiers']['C']['caught']}/{r['tiers']['C']['total']}" for n, r in reports.items()))
    assert not failed, f"tier integrity failed: {failed}"


if __name__ == "__main__":
    if "--tiers" in sys.argv:
        test_tiers()
    else:
        test_golden(update="--update" in sys.argv)
