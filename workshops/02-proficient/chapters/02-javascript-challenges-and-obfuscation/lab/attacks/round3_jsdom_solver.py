"""
Chapter 2 — Round 3 Attack: execute the challenge in jsdom (Section 2.7)

Objective: Round 3 serves a different obfuscated variant on every challenge,
so the Round 2 Python port computes the wrong answer. Stop reading the code
and run it: attacks/js/jsdom_solve.mjs loads the challenge page into jsdom,
lets the variant run, and returns the cookies. We then hand the cookies (and
the same User-Agent, because the clearance is bound to it) to requests.

Cost to the attacker: a Node process and ~100-300 ms per solve. No browser.

Expected results:
  - level 3   → 125/125 records, 1 solve in jsdom
  - level 4+  → 0/125, verify fails: offsetWidth was 0 (no layout engine); DOM methods are not native code

Needs `npm ci` in lab/ (jsdom). Run the store first (python demo_site/app.py), or let
tools/checkpoint.py set the level; then:
    python attacks/round3_jsdom_solver.py
"""

import json
import os
import subprocess
import time

from _common import BASE_URL, CHROME_UA, bot_ip, finish, lab_session, report, result, scrape

SOLVER = os.path.join(os.path.dirname(__file__), "js", "jsdom_solve.mjs")
LAB_DIR = os.path.join(os.path.dirname(__file__), "..")
ACTOR = "round3_jsdom_solver"


def solve_in_jsdom(ip):
    out = subprocess.run(["node", SOLVER, BASE_URL, CHROME_UA, ip, f"bot:{ACTOR}"], capture_output=True,
                         text=True, cwd=LAB_DIR, timeout=60)
    if out.returncode != 0:
        raise RuntimeError(out.stderr.strip() or "jsdom solver failed (did you run `npm ci`?)")
    return json.loads(out.stdout)


def run():
    ip = bot_ip()
    t0 = time.perf_counter()
    solved = solve_in_jsdom(ip)
    solve_seconds = time.perf_counter() - t0
    if not solved["ok"]:
        return result(ACTOR, 0, f"verify failed: {solved.get('reason')}", solve_seconds, 1, solve_seconds)
    session = lab_session(ACTOR, ip=ip)
    for name, value in solved["cookies"].items():
        session.cookies.set(name, value)
    got, reason, seconds, _ = scrape(session)
    return result(ACTOR, got, reason, seconds + solve_seconds, 1, solve_seconds)


if __name__ == '__main__':
    print(f"Round 3 attack: run the challenge in jsdom -> {BASE_URL}")
    r = run()
    report(r)
    finish(r)
