"""
W4 Ch9 Capstone — in-process verification harness (build-time only; not part of the lab)

Starts the store on a background thread in THIS process at a chosen
DEFENSE_LEVEL, waits for it, then runs the round's attack and the legitimate
traffic against 127.0.0.1, and prints the scoreboard. One foreground process,
so it works where detached servers get reaped.

    DEFENSE_LEVEL is set from --round. Student catch-up (solutions -> defenses)
    is applied cumulatively for rounds 1..N when --defended is passed.

    python tools/verify.py --round 0
    python tools/verify.py --round 2 --defended
"""

import argparse
import os
import shutil
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
LAB_DIR = os.path.dirname(HERE)
sys.path.insert(0, LAB_DIR)  # lab root: labnet.py
import labnet  # noqa: E402
PORT = int(os.environ.get("PORT", "8412"))
BASE = f"http://127.0.0.1:{PORT}"
# Every file a round's reference solution replaces (solutions/roundN/<path relative to lab>).
STUDENT_FILES = sorted({dst for _src, dst in labnet.solution_files(LAB_DIR, 4)})
_BACKUPS = {}


def apply_solutions(upto):
    for path in STUDENT_FILES:          # back up the student state so we can restore it after
        with open(path) as f:
            _BACKUPS[path] = f.read()
    for src, dst in labnet.solution_files(LAB_DIR, upto):
        shutil.copy2(src, dst)


def restore_backups():
    for path, text in _BACKUPS.items():
        with open(path, "w") as f:
            f.write(text)


def restore_stubs():
    """Put the student stubs back (git-tracked); solutions are only copied for the defended run."""
    import subprocess
    subprocess.run(["git", "-C", LAB_DIR, "checkout", "--",
                    "defenses/crawl_governance.py", "defenses/agent_governance.py", "defenses/deception_limits.py",
                    "defenses/llm_guard.py", "defenses/oracle_guard.py", "policies/agent_policy.json"],
                   capture_output=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--round", type=int, required=True)
    ap.add_argument("--defended", action="store_true", help="apply solutions 1..round first")
    ap.add_argument("--attack-only", action="store_true")
    ap.add_argument("--checkpoint", action="store_true", help="run the real tools/checkpoint.py in-process")
    ap.add_argument("--ops", action="store_true", help="round 4: triage -> approve -> onboard -> audit")
    args = ap.parse_args()

    if args.defended and args.round >= 1:
        apply_solutions(args.round)

    os.environ["DEFENSE_LEVEL"] = str(args.round if args.defended else 0)
    os.environ["PORT"] = str(PORT)
    os.environ["DEMO_URL"] = BASE
    os.environ.setdefault("LAB_TIME_SCALE", "0.05")
    sys.path.insert(0, os.path.join(LAB_DIR, "demo_site"))
    sys.path.insert(0, os.path.join(LAB_DIR, "defenses"))
    sys.path.insert(0, LAB_DIR)
    sys.path.insert(0, HERE)
    sys.path.insert(0, os.path.join(LAB_DIR, "attacks"))

    from werkzeug.serving import make_server
    import app as store_app
    srv = make_server("127.0.0.1", PORT, store_app.app, threaded=True)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    import requests
    for _ in range(40):
        try:
            requests.get(f"{BASE}/admin/status", timeout=2)
            break
        except Exception:
            time.sleep(0.25)
    print(f"store up at DEFENSE_LEVEL={os.environ['DEFENSE_LEVEL']}  ({BASE})\n")
    import hashlib
    secret = open(os.path.join(LAB_DIR, "instance", "lab_secret")).read().strip()
    admin = {"X-Lab-Admin": hashlib.sha256(f"admin:{secret}".encode()).hexdigest()[:32]}
    requests.post(f"{BASE}/admin/reset?decisions=1&fresh_accounts=1", headers=admin, timeout=10)

    import importlib
    import legit_traffic
    try:
        if args.checkpoint:
            import checkpoint
            sys.argv = ["checkpoint.py", "--round", str(args.round)]
            if args.round == 4:
                sys.argv += ["--record", os.path.join(LAB_DIR, "solutions", "round4", "governance_record.md")]
            return checkpoint.main()
        if args.ops:
            import audit
            import triage
            import subprocess
            print("--- run the agent farm to populate the decision log:")
            importlib.import_module("round2_agent_farm").run(BASE)
            print("\n--- triage proposes a rule from the log:")
            triage.run(BASE)
            import json
            pend = json.load(open(os.path.join(LAB_DIR, "rules", "pending.json")))
            rid = pend["rules"][0]["id"]
            print(f"\n--- a person approves {rid}:")
            subprocess.run([sys.executable, os.path.join(HERE, "approve.py"), "--approve", rid, "--by", "capstone-instructor"])
            print("\n--- a person onboards the new vendor:")
            subprocess.run([sys.executable, os.path.join(HERE, "approve.py"), "onboard-operator",
                            "--host", "agents.newvendor.test", "--by", "capstone-instructor"])
            print("\n--- audit the live store:")
            audit.run(BASE, os.path.join(LAB_DIR, "solutions", "round4", "governance_record.md"))
            return 0
        if args.round == 0:
            importlib.import_module("round0_naive").run(BASE)
        elif args.round == 1:
            importlib.import_module("round1_crawler_fleet").run(BASE)
        elif args.round == 2:
            importlib.import_module("round2_agent_farm").run(BASE)
        elif args.round == 3:
            importlib.import_module("round3_llm_extract").run(BASE)
            print()
            importlib.import_module("round3_injector").run(BASE)
        elif args.round == 4:
            importlib.import_module("round4_integrated").run(BASE)
        if not args.attack_only:
            print("\n=== legitimate traffic ===")
            res = legit_traffic.run(BASE)
            import personas
            for cohort in personas.COHORTS + personas.CRAWLER_COHORTS:
                row = legit_traffic.summarize(res).get(cohort)
                if row:
                    hurt = row["block"] + row["maze"]
                    print(f"  {'OK ' if hurt == 0 else 'BAD'} [{cohort:<16}] allow {row['allow']} challenge {row['challenge']} "
                          f"block {row['block']} maze {row['maze']} other {row['other']}")
            for r in res:
                if r["outcome"] in ("block", "maze", "error"):
                    print(f"       BAD {r['cohort']:<14} {r.get('persona','?'):<16} {r['outcome']:<7} {r.get('reasons', [])[:2]}")
    finally:
        srv.shutdown()
        restore_backups()


if __name__ == "__main__":
    main()
