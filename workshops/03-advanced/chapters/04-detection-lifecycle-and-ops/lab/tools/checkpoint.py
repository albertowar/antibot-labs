"""
Round checkpoint and catch-up

Each round of this chapter is an operations task on a store that has been
running for weeks. The checkpoint drives the whole canonical sequence for a
round from a clean slate and checks the result, so if you fell behind
you can catch up with one command, and you can reproduce every number
in the README.

    python tools/checkpoint.py --round 2          run rounds 0..2 and verify round 2
    python tools/checkpoint.py --round 3 --keep    don't reset first (continue the live state)

What each round does (the reference solution, and what you did by hand):

  0  replay week 1; record the baseline. Nothing gets through, nobody is hurt.
  1  replay week 2; burned signals go silent and the block rate falls. Fix:
     demote the burned signals to intel (weight 0) and lift the behaviour
     signals that still catch the impersonator. (tools/configure.py)
  2  replay week 3; real-user false positives spike and drift fires. Fix:
     refresh the ASN and browser corpora so the edge stops judging real
     users on a stale map. (tools/refresh_corpus.py)
  3  replay week 4; a naive retrain on weak labels is *worse*, and the gate
     refuses it. Fix: label a sample, retrain on it, shadow then canary the
     model that passes the gate. (train.py, gate.py, registry.py, canary.py)
  4  replay week 5; a novel farm reaches accounts. Respond: contain with a
     TTL, snapshot, label, and file the incident report. (contain.py,
     snapshot.py, label.py, incident.py)

The server must be running (REDIS_URL=memory:// python demo_site/app.py).
The checkpoint talks to it over DEMO_URL, exactly as you would.
"""

import argparse
import json
import os
import subprocess
import sys
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
LAB = os.path.join(HERE, "..")
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(LAB, "defenses"))

from report import BASE_URL, by_week, decisions, is_bot, read_log, server_status  # noqa: E402

PY = sys.executable
ACTED = ("block", "pow", "step_up")


def run(*argv, quiet=True):
    """Run a lab tool as you would, from the lab root."""
    cmd = [PY] + list(argv)
    out = subprocess.run(cmd, cwd=LAB, capture_output=True, text=True)
    if not quiet or out.returncode:
        sys.stdout.write(out.stdout)
        sys.stderr.write(out.stderr)
    return out.returncode


def post(path):
    req = urllib.request.Request(f"{BASE_URL}{path}", method="POST")
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read())


def weeks_tool(*extra):
    return run("tools/weeks.py", *extra, "--quiet")


def grade(es):
    tp = fp = fn = 0
    bots = humans = 0
    for e in es:
        acted = e["enforced"] in ACTED
        if is_bot(e):
            bots += 1
            tp += acted
            fn += not acted
        else:
            humans += 1
            fp += acted
    wins = sum(1 for e in es if is_bot(e) and e["cred"] == "valid" and e["enforced"] in ("allow", "pow"))
    blocked_bots = sum(1 for e in es if is_bot(e) and e["enforced"] == "block")
    hurt = sum(1 for e in es if not is_bot(e) and e["enforced"] in ACTED)
    return {"bots": bots, "humans": humans, "tp": tp, "fp": fp, "fn": fn, "wins": wins,
            "bot_block_rate": blocked_bots / bots if bots else 0,
            "hurt_rate": hurt / humans if humans else 0, "hurt": hurt}


def solve(target, keep):
    """Drive rounds 0..target. Each round applies its fix, then replays its
    week, so the week is scored under the fixed stack (what catching up means)."""
    if not keep:
        post("/lab/reset")
    # Round 0: baseline week, rules only.
    weeks_tool("--week", "1")
    if target >= 1:
        # Round 1: demote the burned signal, lift the behaviour signals that
        # still catch the impersonator, then replay the week.
        run("tools/configure.py", "--weight", "header_order_mismatch=0",
            "--weight", "mouse_too_straight=25", "--weight", "timing_too_regular=25",
            "--note", "R1: header order burned; behaviour re-weighted")
        weeks_tool("--week", "2")
    if target >= 2:
        # Round 2: refresh the stale corpora so the edge stops judging real
        # users on a week-0 map, then replay the week. Introduce the W2 Ch7
        # model as prod from here on (trained on the clean weeks).
        run("tools/refresh_corpus.py", "--all", "--week", "3")
        run("defenses/train.py", "--weeks", "1-2", "--labels", "weak")
        run("tools/roles.py", "promote", "v1")
        weeks_tool("--week", "3")
    if target >= 3:
        # Round 3: week 4 arrives with v1 acting. A naive retrain on weak
        # labels is poisoned and the gate refuses it; a labelled retrain
        # passes and ships via shadow -> canary.
        weeks_tool("--week", "4")
        run("defenses/train.py", "--weeks", "2-4", "--labels", "weak")          # v2: poisoned
        run("tools/label.py", "--cluster", _top_bot_cluster(4), "--as", "bot", "--week", "4")
        _label_human_sample(4)
        run("defenses/train.py", "--weeks", "2-4", "--labels", "weak+analyst")  # v3
        run("tools/roles.py", "shadow", "v3")
        run("tools/roles.py", "canary", "v3")
        run("tools/canary.py", "--pct", "50")
    if target >= 4:
        # Round 4: week 5's novel farm reaches accounts. Respond: preserve
        # evidence, label it, file the report, then contain the exit ASN with
        # a TTL. Week 6 is the containment window: the farm keeps coming, now
        # stopped, at the cost of challenging that ISP's real customers.
        weeks_tool("--week", "5")
        run("tools/snapshot.py", "--week", "5", "--label", "inc-2026-05")
        run("tools/label.py", "--cluster", _top_bot_cluster(5), "--as", "bot", "--week", "5")
        run("tools/incident.py", "--week", "5", "--id", "INC-2026-05")
        run("tools/contain.py", "--step-up-asn", "64496", "--for-weeks", "1")
        weeks_tool("--week", "6")


def _top_bot_cluster(week):
    from collections import Counter
    es = by_week(decisions(read_log()), week)
    c = Counter(e["cluster"] for e in es if is_bot(e))
    return c.most_common(1)[0][0] if c else "none"


def _label_human_sample(week):
    """Label a handful of real customers human, so the analyst set has both classes."""
    es = [e for e in by_week(decisions(read_log()), week) if not is_bot(e)][:12]
    sys.path.insert(0, os.path.join(LAB, "defenses"))
    import labels
    labels.add([{"sid": e["sid"], "label": "human", "source": "analyst",
                 "week": week, "note": "checkpoint human sample"} for e in es])


# Per-round expectations (verified; see README expected-results table).
def check(target):
    week_of = {0: 1, 1: 2, 2: 3, 3: 4, 4: 5}[target]
    es = by_week(decisions(read_log()), week_of)
    es6 = by_week(decisions(read_log()), 6) if target == 4 else []
    g = grade(es)
    print(f"=== Checkpoint: Round {target} (lab week {week_of}) ===\n")
    print(f"  bots {g['bots']}, real users {g['humans']}")
    print(f"  bot block rate {100 * g['bot_block_rate']:.0f}%  |  bots that reached an account {g['wins']}")
    print(f"  real users hurt {g['hurt']}/{g['humans']} ({100 * g['hurt_rate']:.1f}%)")

    fails = []
    if target == 0:
        if g["bot_block_rate"] < 0.9:
            fails.append(f"baseline should block ~all bots, got {100 * g['bot_block_rate']:.0f}%")
        if g["hurt_rate"] > 0.1:
            fails.append(f"baseline hurts {100 * g['hurt_rate']:.0f}% of users, expected <10%")
    if target == 1:
        rc = run("tools/alerts.py", "--week", "2", quiet=True)
        if g["bot_block_rate"] < 0.85:
            fails.append(f"after re-weighting, bot block rate {100 * g['bot_block_rate']:.0f}% < 85%")
        if g["hurt_rate"] > 0.08:
            fails.append(f"re-weighting hurt {100 * g['hurt_rate']:.0f}% of users, budget 8%")
    if target == 2:
        blocked_users = sum(1 for e in es if not is_bot(e) and e["enforced"] == "block")
        if blocked_users:
            fails.append(f"after the corpus refresh, {blocked_users} real users still blocked by stale data")
        if g["hurt_rate"] > 0.055:
            fails.append(f"after the refresh, {100 * g['hurt_rate']:.1f}% of users hurt, baseline ~4%")
    if target == 3:
        from registry import load
        roles = load()["roles"]
        if roles.get("canary") != "v3":
            fails.append(f"canary should be v3, is {roles.get('canary')}")
        gate_rc = run("defenses/gate.py", "--candidate", "v2", "--week", "4", quiet=True)
        if gate_rc == 0:
            fails.append("the poisoned v2 should have been REFUSED by the gate, but it passed")
    if target == 4:
        if g["wins"] == 0:
            fails.append("week 5's novel farm should reach at least one account (that is the lesson)")
        if not os.path.exists(os.path.join(LAB, "incident", "incident_report.md")):
            fails.append("no incident report was written")
        g6 = grade(es6)
        farm6 = [e for e in es6 if e["actor"] == "bot:humanized_farm"]
        farm6_in = sum(1 for e in farm6 if e["cred"] == "valid" and e["enforced"] in ("allow", "pow"))
        hurt6 = sum(1 for e in es6 if not is_bot(e) and e["enforced"] in ACTED)
        print(f"  containment window (week 6): farm reached {farm6_in} accounts "
              f"(was {g['wins']} uncontained); real users challenged {hurt6}/{g6['humans']} "
              f"({100 * g6['hurt_rate']:.1f}%) <- the cost of a blunt ASN step-up")
        if farm6_in >= g["wins"]:
            fails.append("containment did not reduce the accounts the farm reached")
        if g6["hurt_rate"] <= g["hurt_rate"]:
            fails.append("blunt ASN containment should visibly cost real users on that ISP")

    print()
    if fails:
        for f in fails:
            print(f"❌ {f}")
        print("\n   Compare with the Expected results table in README.md.")
        return 1
    print(f"✅ Round {target} checkpoint passed.")
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    parser.add_argument("--round", type=int, required=True, choices=range(0, 5))
    parser.add_argument("--keep", action="store_true", help="don't reset the store first")
    args = parser.parse_args()
    try:
        server_status()
    except OSError:
        print("Demo site not reachable. Start it:\n"
              "    REDIS_URL=memory:// python demo_site/app.py")
        return 1
    solve(args.round, args.keep)
    return check(args.round)


if __name__ == "__main__":
    sys.exit(main())
