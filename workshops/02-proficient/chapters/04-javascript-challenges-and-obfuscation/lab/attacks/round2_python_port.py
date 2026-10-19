"""
Chapter 4 — Round 2 Attack: port the solver to Python (Section 4.7)

Objective: the Round 2 challenge is signed, bound to our session and single use, so forging or
replaying no longer works (run with --replay to see each attempt fail). But /jsc/l2.js is plain,
readable JavaScript. Read step() once, port it to Python, and solve every challenge without a
browser at ~0.1 ms per solve.

This is the attack that obfuscation and polymorphism (Round 3) exist to make expensive: not
impossible, expensive.

Expected results:
  - level 2   → 125/125 records, 1 solve
  - level 3+  → 0/125, verify fails: "wrong answer" (each variant has its own op chain)

Run the store first (python demo_site/app.py), or let tools/checkpoint.py set the level; then:
    python attacks/round2_python_port.py
    python attacks/round2_python_port.py --replay
"""

import argparse
import time

from _common import BASE_URL, challenge_payload, finish, lab_session, report, result, scrape, verify

MASK = 0xFFFFFFFF


def step(h, c):
    # Ported by hand from step() in /jsc/l2.js:
    #   h = Math.imul(h, 0x01000193) >>> 0;
    #   h = ((h << 5) | (h >>> 27)) >>> 0;
    #   h = (h + 0x9e3779b9) >>> 0;
    h = (h ^ c) & MASK
    h = (h * 0x01000193) & MASK
    h = ((h << 5) | (h >> 27)) & MASK
    h = (h + 0x9E3779B9) & MASK
    return h


def solve(nonce):
    h = 0x811C9DC5
    for ch in nonce:
        h = step(h, ord(ch))
    return f"{h:08x}"


def get_clearance(session):
    """Take the challenge the gate hands out, solve it in Python, redeem it. Returns (ok, reason, payload)."""
    ch = challenge_payload(session)
    if not ch or "nonce" not in ch:
        return False, f"no signed challenge here ({ch})", None
    ok, reason = verify(session, ch["token"], solve(ch["nonce"]))
    return ok, reason, ch


def run():
    session = lab_session("round2_python_port")
    t0 = time.perf_counter()
    ok, reason, _ = get_clearance(session)
    solve_seconds = time.perf_counter() - t0
    if not ok:
        return result("round2_python_port", 0, f"verify failed: {reason}", solve_seconds, 1, solve_seconds)
    got, reason, seconds, _ = scrape(session)
    return result("round2_python_port", got, reason, seconds + solve_seconds, 1, solve_seconds)


def replay_attempts():
    """What Round 2's binding and single use break. Each line after the first should fail."""
    a = lab_session("round2_replay")
    ok, reason, ch = get_clearance(a)
    print(f"  solve + redeem once (session A)          -> {'accepted' if ok else 'refused: ' + str(reason)}")
    if not ok:
        return
    again, why = verify(a, ch["token"], solve(ch["nonce"]))
    print(f"  redeem the same token again              -> {'accepted' if again else 'refused: ' + str(why)}")

    b = lab_session("round2_replay")                    # a second worker, its own cookie jar
    r = b.get(f"{BASE_URL}/api/products", timeout=10)
    print(f"  session B, its own cookies               -> {r.status_code}")

    c = lab_session("round2_replay", ua="python-requests/2.34")   # copy A's cookies, forget the UA
    c.cookies.update(a.cookies)
    r = c.get(f"{BASE_URL}/api/products", timeout=10)
    print(f"  copy A's cookies, default requests UA    -> {r.status_code}  (the pass was granted to A's UA)")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Round 2 attack: Python port of the challenge")
    parser.add_argument("--replay", action="store_true", help="show the replay attempts Round 2 stops")
    args = parser.parse_args()
    if args.replay:
        print(f"Round 2: replay and sharing attempts -> {BASE_URL}")
        replay_attempts()
    else:
        print(f"Round 2 attack: Python port of /jsc/l2.js -> {BASE_URL}")
        r = run()
        report(r)
        finish(r)
