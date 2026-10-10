"""
Chapter 2 — Full scoreboard: every round, every level, one command (Section 2.7, debrief)

Starts its own copy of the demo site at DEFENSE_LEVEL 0..5 (one after the
other, on SCOREBOARD_PORT, default 5151), runs that round's checkpoint
(attacks + real users), and prints the debrief table: what each defense
stopped, what got through, who it hurt, and what it cost.

Instructors: run this before class to fill in the expected-results table,
and again after any browser or Playwright upgrade.

Run (from lab/, with the venv active; Redis optional):
    python tools/scoreboard.py
    python tools/scoreboard.py --skip-browser      # quick, but no FP numbers
"""

import argparse
import os
import subprocess
import sys
import time
import urllib.request

PORT = int(os.environ.get("SCOREBOARD_PORT", "5151"))
os.environ["DEMO_URL"] = f"http://localhost:{PORT}"     # before importing the tools

LAB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import checkpoint      # noqa: E402  (needs DEMO_URL set first)
import legit_traffic   # noqa: E402


def start_site(level):
    env = dict(os.environ, DEFENSE_LEVEL=str(level), PORT=str(PORT))
    proc = subprocess.Popen([sys.executable, "app.py"], cwd=os.path.join(LAB_DIR, "demo_site"),
                            env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(50):
        try:
            urllib.request.urlopen(f"http://localhost:{PORT}/challenge-check", timeout=1)
            return proc
        except OSError:
            time.sleep(0.2)
    proc.kill()
    sys.exit(f"❌ Demo site did not start on port {PORT} (in use? set SCOREBOARD_PORT)")


def main():
    parser = argparse.ArgumentParser(description="Run every round and print the debrief table")
    parser.add_argument("--skip-browser", action="store_true")
    args = parser.parse_args()

    rows, legit_rows, cost_rows = {}, {}, {}
    for level in range(6):
        print(f"\n=== DEFENSE_LEVEL={level} ===")
        site = start_site(level)
        try:
            results, failures = checkpoint.run_attacks(level, args.skip_browser)
            for r in results:
                rows.setdefault(r["attack"], {})[level] = r
            if not args.skip_browser:
                legit = legit_traffic.run()
                legit_rows[level] = legit
            cost_rows[level] = checkpoint.script_bytes(level)
        finally:
            site.terminate()
            site.wait()

    print("\n\n=== Scoreboard: pages scraped out of 300 (blank = attack not yet invented) ===\n")
    print(f"  {'attack':<28}" + "".join(f"  L{lvl:<4}" for lvl in range(6)))
    for attack, by_level in rows.items():
        cells = "".join(f"  {by_level[lvl]['pages_ok']:<5}" if lvl in by_level else "       "
                        for lvl in range(6))
        print(f"  {attack:<28}{cells}")
    if legit_rows:
        hurt = {lvl: sum(1 for r in rs if not r["nojs"] and
                         (r["pages_ok"] < r["pages_total"] or r["challenges_failed"]))
                for lvl, rs in legit_rows.items()}
        js_users = sum(1 for r in legit_rows[0] if not r["nojs"])
        print(f"  {'real JS users hurt':<28}" + "".join(f"  {hurt[l]}/{js_users:<3}" for l in range(6)))
        nojs = {lvl: next((r for r in rs if r["nojs"]), None) for lvl, rs in legit_rows.items()}
        print(f"  {'no-JS user pages':<28}" + "".join(
            f"  {nojs[l]['pages_ok']}/{nojs[l]['pages_total']:<3}" if nojs[l] else "       "
            for l in range(6)))
    print(f"  {'challenge script KB':<28}" + "".join(
        f"  {cost_rows[l] / 1024:<5.1f}" if cost_rows[l] else "  -    " for l in range(6)))


if __name__ == '__main__':
    main()
