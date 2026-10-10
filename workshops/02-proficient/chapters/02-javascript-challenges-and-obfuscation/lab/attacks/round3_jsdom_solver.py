"""
Chapter 2 — Round 3 Attack: execute the challenge in jsdom (Section 2.7)

Objective: Round 3 serves a different obfuscated variant on every challenge,
so the Round 2 Python port computes the wrong answer. Stop reading the code
and run it: attacks/js/jsdom_solve.mjs loads the challenge page into jsdom,
lets the variant run, and returns the cookies. We then hand the cookies (and
the same User-Agent, because the clearance is bound to it) to requests.

Cost to the attacker: a Node process and ~100-300 ms per solve. No browser.

Expected results:
  - DEFENSE_LEVEL=2,3 → 300/300 pages, 1 solve
  - DEFENSE_LEVEL>=4  → 0/300, verify fails: "offsetWidth was 0 (no layout
                        engine); DOM methods are not native code"

Run the demo site first:
    cd demo_site && DEFENSE_LEVEL=3 python app.py
Then run:
    python attacks/round3_jsdom_solver.py
"""

import json
import os
import subprocess
import time

import requests

from common import BASE_URL, CHROME_UA, report, require_local, result, scrape

SOLVER = os.path.join(os.path.dirname(__file__), "js", "jsdom_solve.mjs")
LAB_DIR = os.path.join(os.path.dirname(__file__), "..")


def solve_in_jsdom():
    out = subprocess.run(["node", SOLVER, BASE_URL, CHROME_UA], capture_output=True,
                         text=True, cwd=LAB_DIR, timeout=30)
    if out.returncode != 0:
        raise RuntimeError(out.stderr.strip() or "jsdom solver failed (did you run `npm ci`?)")
    return json.loads(out.stdout)


def run():
    require_local()
    t0 = time.perf_counter()
    solved = solve_in_jsdom()
    solve_seconds = time.perf_counter() - t0
    if not solved["ok"]:
        return result("round3_jsdom_solver", 0, f"verify failed: {solved['reason']}",
                      solve_seconds, 1, solve_seconds)
    session = requests.Session()
    session.headers["User-Agent"] = CHROME_UA
    for name, value in solved["cookies"].items():
        session.cookies.set(name, value)
    pages, reason, seconds = scrape(session)
    return result("round3_jsdom_solver", pages, reason, seconds + solve_seconds, 1, solve_seconds)


if __name__ == '__main__':
    print(f"Round 3 attack: run the challenge in jsdom -> {BASE_URL}")
    report(run())
