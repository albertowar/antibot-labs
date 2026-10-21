"""
Round checkpoint for W3 Ch10 (Detection Signal Lifecycle & Ops). Declares the rounds and hands over to
checkpoint_core (whose check_round is wrapped below: this chapter's rounds are *weeks of operations*,
not a population run).

    python tools/checkpoint.py --round 2                 # rebuild weeks 1..3 with every fix up to Round 2, verify
    python tools/checkpoint.py --round 2 --level 1       # the same week with only Round 1's fix: the "before" column
    python tools/checkpoint.py --round 2 --no-reset      # judge the live store as it stands (your own hand-driven run)
    python tools/checkpoint.py --round 2 --catch-up      # also install the operator-state files of rounds 1..2
    python tools/checkpoint.py --restore                 # nothing to restore: no student file is replaced
    python tools/checkpoint.py --all --markdown          # every round (the README's expected-results table)

This lab is PRE-WRITTEN: every control ships complete (defenses/ladder.py wires the whole stack at level 1), and
what a round changes is *operational state*: data/ops_config.json, data/world_updates.json,
models/manifest.json, data/labels.jsonl. `--level N` therefore means "the fixes of rounds 1..N are in
force". The store itself runs at DEFENSE_LEVEL 1 throughout (0 is the bare store). The checkpoint always starts from a clean slate and rebuilds the history,
so it IS the reference solution: read `history()` to see the exact operator commands.

    round  week measured  the problem                          the fix (tools/)                            what the checkpoint asserts
    -----  -------------  -----------------------------------  ------------------------------------------  ----------------------------------------
      0    1              none: the stack wins                 (record the baseline)                       every bot stopped, <10% of customers hurt
      1    2              burned signals go silent             configure.py: kill one, lift two            bots stopped again, silent alert fired
      2    3              the world moved: stale data          refresh_corpus.py, train.py v1, promote     no customer blocked by stale data
      3    4              the retrain feedback loop            label.py, train.py, gate.py, roles.py       gate refuses v2, passes v3, v3 is canary
      4    5, then 6      a signal-less farm reaches accounts  snapshot, incident, contain.py (with a TTL) farm reaches 0 accounts, at a visible cost

Weeks 1..N run live through the store with every request stamped on the lab calendar; the scoreboard
tools (ops.py, alerts.py) read the same decision log you do.
"""

import os
import shutil
import subprocess
import sys
import time
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import checkpoint_core as core  # noqa: E402
import health  # noqa: E402
import labclient  # noqa: E402
import ops_reset  # noqa: E402
import report  # noqa: E402
import weeks  # noqa: E402
from checkpoint_core import Round  # noqa: E402
from report import ACTED, by_week, is_bot  # noqa: E402

LAB = core.LAB
PY = sys.executable
OPERATED = 1                                    # DEFENSE_LEVEL of the operated stack (0 is the bare store)
WEEK_OF = {0: 1, 1: 2, 2: 3, 3: 4, 4: 5}        # the week each round is about (round 4 also plays week 6)
GATE_MEDIAN_MAX_MS = 30.0                       # in-process Redis
GATE_MEDIAN_MAX_MS_REDIS = 250.0                # a real Redis: ~10 round trips per sign-in
INCIDENT = os.path.join(LAB, "incident", "incident_report.md")

ROUNDS = {
    0: Round(level=0, description="baseline: a stack that wins"),
    1: Round(level=1, description="a signal goes quiet: demote what burned, lift what still works",
             solutions=("data/ops_config.json",)),
    2: Round(level=2, description="the world moves: refresh the data, ship a model as one more sensor",
             solutions=("data/world_updates.json",)),
    3: Round(level=3, description="retrain without poisoning yourself: labels, gate, shadow, canary", solutions=()),
    4: Round(level=4, description="one slips through: preserve, contain with a TTL, report", solutions=()),
}


# --- the operator's commands (the reference solution) ----------------------------------------------

def run(*argv):
    """Run a lab tool exactly as a learner would, from the lab root."""
    out = subprocess.run([PY, *argv], cwd=LAB, capture_output=True, text=True)
    if out.returncode and not (argv[0].endswith("gate.py")):
        sys.stdout.write(out.stdout + out.stderr)
        raise SystemExit(f"tool failed: {' '.join(argv)}")
    return out.returncode, out.stdout


def top_bot_cluster(week):
    es = by_week(report.read_log(), week)
    clusters = Counter(e["cluster"] for e in es if is_bot(e))
    return clusters.most_common(1)[0][0]


def label_human_sample(week):
    """Label a handful of real customers human, so the analyst set has both classes."""
    import labels
    es = [e for e in by_week(report.read_log(), week) if not is_bot(e)][:12]
    labels.add([{"sid": e["sid"], "label": "human", "source": "analyst", "week": week,
                 "note": "checkpoint human sample"} for e in es])


def fix1():
    """Round 1: week 2 showed three signals going quiet. Kill the one that burned, lift the two behaviour signals
    the impersonator still trips."""
    run("tools/configure.py", "--weight", "header_order_mismatch=0", "--weight", "mouse_too_straight=25",
        "--weight", "timing_too_regular=25", "--note", "R1: header order burned; behaviour re-weighted")


def fix2():
    """Round 2: refresh the data the sensors depend on, and put the W2 Ch7 model into production as one more
    sensor (trained on the clean weeks)."""
    run("tools/refresh_corpus.py", "--all", "--week", "3")
    run("tools/train.py", "--weeks", "1-2", "--labels", "weak")
    run("tools/roles.py", "promote", "v1")


def fix3():
    """Round 3: the naive retrain is poisoned and the gate refuses it; a labelled retrain passes and ships via
    shadow, then canary."""
    run("tools/train.py", "--weeks", "2-4", "--labels", "weak")                       # v2: poisoned
    run("tools/label.py", "--cluster", top_bot_cluster(4), "--as", "bot", "--week", "4")
    label_human_sample(4)
    run("tools/train.py", "--weeks", "2-4", "--labels", "weak+analyst")               # v3
    run("tools/roles.py", "shadow", "v3")
    run("tools/roles.py", "canary", "v3")
    run("tools/canary.py", "--pct", "50")


def fix4():
    """Round 4: preserve the evidence, label the farm, file the report, then contain the exit ASN with a TTL."""
    run("tools/snapshot.py", "--week", "5", "--label", "inc-2026-05")
    run("tools/label.py", "--cluster", top_bot_cluster(5), "--as", "bot", "--week", "5")
    run("tools/incident.py", "--week", "5", "--id", "INC-2026-05")
    run("tools/contain.py", "--step-up-asn", "64496", "--for-weeks", "1")


def history(n, fixed):
    """Weeks 1..N (and week 6 for Round 4) with the fixes of rounds 1..`fixed` in force. Each fix is applied
    where the chapter applies it: before the week it protects, except Rounds 3 and 4, which respond to a week
    that has already happened."""
    weeks.replay_week(1, quiet=True)
    if n >= 1:
        if fixed >= 1:
            fix1()
        weeks.replay_week(2, quiet=True)
    if n >= 2:
        if fixed >= 2:
            fix2()
        weeks.replay_week(3, quiet=True)
    if n >= 3:
        weeks.replay_week(4, quiet=True)
        if fixed >= 3:
            fix3()
    if n >= 4:
        weeks.replay_week(5, quiet=True)
        if fixed >= 4:
            fix4()
        weeks.replay_week(6, quiet=True)


# --- the numbers -----------------------------------------------------------------------------------------

def grade(es):
    bots = [e for e in es if is_bot(e)]
    humans = [e for e in es if not is_bot(e)]
    # a proof-of-work is solved by the bot, so only a (deceptive) block or an unanswerable step-up stops it
    stopped = sum(1 for e in bots if e["enforced"] in ("block", "step_up"))
    hurt = [e for e in humans if e["enforced"] in ACTED]
    return {"bots": len(bots), "humans": len(humans), "bot_stopped": stopped / len(bots) if bots else 0.0,
            "reached": sum(1 for e in bots if e["reached"]), "hurt": len(hurt),
            "hurt_rate": len(hurt) / len(humans) if humans else 0.0,
            "blocked_humans": sum(1 for e in humans if e["enforced"] == "block"),
            "challenged_humans": sum(1 for e in humans if e["enforced"] in ("pow", "step_up")),
            "gate_ms": [e["ms"] for e in es if e.get("ms") is not None]}


def row(week, label, g, markdown):
    cells = [week, label, g["bots"], f"{100 * g['bot_stopped']:.0f}%", g["reached"],
             f"{g['hurt']} ({100 * g['hurt_rate']:.1f}%): {g['blocked_humans']} blocked, {g['challenged_humans']} challenged"]
    return "| " + " | ".join(str(c) for c in cells) + " |" if markdown else \
        f"  week {week} [{label}]: {g['bots']} bots, {100 * g['bot_stopped']:.0f}% stopped, " \
        f"{g['reached']} reached an account, {cells[5]} customers hurt, {g['humans']} customers"


def matches_solution(rel, n):
    """The state file the operator's commands wrote is the one solutions/round<n>/ ships (and --catch-up installs)."""
    src, dst = os.path.join(LAB, "solutions", f"round{n}", rel), os.path.join(LAB, rel)
    return os.path.exists(dst) and open(src).read().strip() == open(dst).read().strip()


def verify_round(n, fixed, log, markdown):
    """Judge round n. Returns a list of problems and prints the numbers."""
    problems = []
    week = WEEK_OF[n]
    es = by_week(log, week)
    g = grade(es)
    g6 = None
    if markdown:
        print("\n| Week | Round | Bots | Bots stopped | Bots that reached an account | Customers hurt (acted on) |\n|---|---|---|---|---|---|")
    print(row(week, f"R{n}" + ("" if fixed == n else f" with fixes through R{fixed}"), g, markdown))
    if n == 4:
        g6 = grade(by_week(log, 6))
        print(row(6, "R4 containment window" if fixed >= 4 else "R4 week 6, uncontained", g6, markdown))
    if g["gate_ms"]:
        median, p95 = report.percentiles(g["gate_ms"])
        limit = GATE_MEDIAN_MAX_MS if labclient.admin("GET", "/lab/config")["redis_url"].startswith("memory") \
            else GATE_MEDIAN_MAX_MS_REDIS
        print(f"  defender cost: gate median {median:.2f} ms, p95 {p95:.2f} ms per sign-in")
        if median > limit:
            problems.append(f"gate median {median:.2f} ms > {limit} ms")

    if n == 0:
        if g["bot_stopped"] < 0.9:
            problems.append(f"baseline should stop ~all bots, stopped {100 * g['bot_stopped']:.0f}%")
        if g["hurt_rate"] > 0.10:
            problems.append(f"baseline hurts {100 * g['hurt_rate']:.0f}% of customers, expected <10%")
    if n == 1:
        alerts = health.alerts(health.per_week(log), 2)
        silent = [m for sev, rule, m in alerts if rule == "silent"]
        print(f"  silent-signal alerts for week 2: {len(silent)} ({'; '.join(m.split(':')[0] for m in silent)})")
        if not silent:
            problems.append("week 2 should raise a silent-signal alert (a burned signal)")
        if g["bot_stopped"] < 0.95:
            problems.append(f"after re-weighting, bots stopped {100 * g['bot_stopped']:.0f}% < 95%")
        if g["hurt_rate"] > 0.08:
            problems.append(f"re-weighting hurt {100 * g['hurt_rate']:.1f}% of customers, budget 8%")
        if fixed >= 1 and not matches_solution("data/ops_config.json", 1):
            problems.append("data/ops_config.json differs from solutions/round1/ (configure.py and the solution disagree)")
    if n == 2:
        if g["blocked_humans"]:
            problems.append(f"after the corpus refresh, {g['blocked_humans']} customers are still blocked by stale data")
        if g["hurt_rate"] > 0.055:
            problems.append(f"after the refresh, {100 * g['hurt_rate']:.1f}% of customers hurt, baseline ~4%")
        if fixed >= 2 and not matches_solution("data/world_updates.json", 2):
            problems.append("data/world_updates.json differs from solutions/round2/ (refresh_corpus.py and the solution disagree)")
        kg = [m for sev, rule, m in health.alerts(health.per_week(log), 3) if rule == "known_good"]
        if kg:
            problems.append("the known-good cohort still trips: " + "; ".join(kg))
    if n == 3:
        from defenses import registry
        roles = registry.load()["roles"]
        if fixed >= 3:
            rc2, _ = run("tools/gate.py", "--candidate", "v2", "--week", "4")
            rc3, _ = run("tools/gate.py", "--candidate", "v3", "--week", "4")
            print(f"  gate: v2 {'REFUSED' if rc2 else 'PASSED'}, v3 {'PASSED' if not rc3 else 'REFUSED'}; roles {roles}")
            if rc2 == 0:
                problems.append("the poisoned v2 should have been REFUSED by the gate, but it passed")
            if rc3 != 0:
                problems.append("the labelled v3 should have PASSED the gate")
            if roles.get("canary") != "v3" or roles.get("shadow") != "v3" or roles.get("prod") != "v1":
                problems.append(f"expected prod v1 + shadow/canary v3, got {roles}")
        else:
            print(f"  no candidate yet (fixes through Round {fixed}); roles {roles}")
        if g["reached"] == 0:
            problems.append("week 4's evader should reach accounts (that is the lesson)")
    if n == 4:
        if g["reached"] == 0:
            problems.append("week 5's novel farm should reach at least one account (that is the lesson)")
        if fixed >= 4:
            if not os.path.exists(INCIDENT):
                problems.append("no incident report was written")
            if g6["reached"] >= g["reached"]:
                problems.append("containment did not reduce the accounts the farm reached")
            if g6["hurt_rate"] <= g["hurt_rate"]:
                problems.append("blunt ASN containment should visibly cost real customers on that ISP")
            print(f"  containment: farm reached {g6['reached']} accounts (was {g['reached']} uncontained); "
                  f"{g6['hurt']}/{g6['humans']} customers challenged ({100 * g6['hurt_rate']:.1f}%) "
                  "<- the cost of a blunt ASN step-up")
    return problems, g


def check_round(rounds, n, markdown=False, reset_store=True, level=None):
    """Replaces checkpoint_core.check_round. `level` is "the fixes of rounds 1..level are in force"."""
    fixed = n if level is None else level
    labclient.wait_for_store()
    print(f"\n== Round {n}: {rounds[n].description} (fixes through Round {fixed})")
    labclient.set_level(OPERATED)               # the operated stack; a round changes state, not the level
    if reset_store:
        ops_reset.reset()
        started = time.perf_counter()
        history(n, fixed)
        print(f"  (replayed {n + 1 if n < 4 else 6} lab weeks in {time.perf_counter() - started:.0f}s of wall clock)")
    log = report.read_log()
    if not log:
        raise SystemExit("The decision log is empty. Replay a week first: python tools/weeks.py --week 1")
    problems, g = verify_round(n, fixed, log, markdown)
    judge = level is None
    ok = not (problems and judge)
    print(f"\nRound {n} with fixes through Round {fixed}: " + ("PASS" if ok else "FAIL")
          + ("" if ok else "\n  - " + "\n  - ".join(problems))
          + ("" if judge or not problems else "\n  (reported, not judged: this is the 'before' column)"))
    return {"round": n, "level": fixed, "ok": ok, "bot_success": round(g["reached"] / g["bots"], 3) if g["bots"] else 0.0,
            "humans_hurt": g["hurt"], "problems": problems, "attacks": {}, "summary": {}}


def catch_up_state(rounds, upto):
    """Install the operator-state files of rounds 1..upto (solutions/roundN/data/...). They are state the
    checkpoint rebuilds, not files you wrote, so unlike a wire-it lab nothing is backed up and --restore
    has nothing to put back."""
    for n in range(1, upto + 1):
        for rel in rounds[n].solutions if n in rounds else ():
            src, dst = os.path.join(LAB, "solutions", f"round{n}", rel), os.path.join(LAB, rel)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            shutil.copy2(src, dst)
            print(f"  installed solutions/round{n}/{rel}")


core.check_round = check_round        # verify.py and checkpoint_core.main call these by attribute
core.catch_up = catch_up_state

if __name__ == "__main__":
    core.main(ROUNDS)
