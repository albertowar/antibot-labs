"""
Chapter 2 — Round 2 Attack: port the solver to Python (Section 2.7)

Objective: the Round 2 challenge is signed, bound to our session and single
use, so forging or replaying a cookie no longer works (run with --replay to
see each attempt fail). But /challenge/l2.js is plain, readable JavaScript.
Read step() once, port it to Python, and solve every challenge without a
browser at ~0.1 ms per solve.

This is the attack that obfuscation and polymorphism (Round 3) exist to
make expensive: not impossible, expensive.

Expected results:
  - DEFENSE_LEVEL=2   → 300/300 pages, 1 solve
  - DEFENSE_LEVEL>=3  → 0/300, verify fails: "wrong answer" (each variant has its own op chain)

Run the demo site first:
    cd demo_site && DEFENSE_LEVEL=2 python app.py
Then run:
    python attacks/round2_python_port.py
    python attacks/round2_python_port.py --replay
"""

import argparse
import time

import requests

from common import BASE_URL, CHROME_UA, report, require_local, result, scrape

MASK = 0xFFFFFFFF


def step(h, c):
    # Ported by hand from step() in /challenge/l2.js:
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


def new_session():
    session = requests.Session()
    session.headers["User-Agent"] = CHROME_UA
    session.get(f"{BASE_URL}/", timeout=10)          # picks up the sid cookie
    return session


def get_clearance(session):
    """Fetch a challenge, solve it in Python, redeem it. Returns (ok, reason, challenge)."""
    r = session.post(f"{BASE_URL}/challenge/new", timeout=10)
    if r.status_code != 200:
        return False, f"/challenge/new -> {r.status_code}", None
    ch = r.json()
    answer = solve(ch["nonce"])
    v = session.post(f"{BASE_URL}/challenge/verify", timeout=10,
                     json={"token": ch["token"], "answer": answer, "solve_ms": 0.1})
    return v.status_code == 200, v.json().get("reason"), ch


def run():
    require_local()
    session = new_session()
    t0 = time.perf_counter()
    ok, reason, _ = get_clearance(session)
    solve_seconds = time.perf_counter() - t0
    if not ok:
        return result("round2_python_port", 0, f"verify failed: {reason}", solve_seconds, 1, solve_seconds)
    pages, reason, seconds = scrape(session)
    return result("round2_python_port", pages, reason, seconds + solve_seconds, 1, solve_seconds)


def replay_attempts():
    """What Round 2's binding and single use break. Each line should fail."""
    require_local()
    a = new_session()
    ok, reason, ch = get_clearance(a)
    print(f"  solve + redeem once (session A)          -> {'accepted' if ok else 'refused: ' + str(reason)}")
    if not ok:
        return
    again = a.post(f"{BASE_URL}/challenge/verify", timeout=10,
                   json={"token": ch["token"], "answer": solve(ch["nonce"])})
    print(f"  redeem the same token again              -> {again.status_code}: {again.json().get('reason')}")

    b = new_session()                                   # a second worker, its own sid
    b.cookies.set("clr", a.cookies.get("clr"))
    r = b.get(f"{BASE_URL}/api/products", timeout=10)
    print(f"  share A's clearance with session B       -> {r.status_code}: {r.json().get('reason')}")

    c = requests.Session()                              # copy BOTH cookies, but forget the UA
    c.cookies.update(a.cookies)
    r = c.get(f"{BASE_URL}/api/products", timeout=10)
    print(f"  copy A's cookies, default requests UA    -> {r.status_code}: {r.json().get('reason')}")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Round 2 attack: Python port of the challenge")
    parser.add_argument("--replay", action="store_true", help="show the replay attempts Round 2 stops")
    args = parser.parse_args()
    if args.replay:
        print(f"Round 2: replay and sharing attempts -> {BASE_URL}")
        replay_attempts()
    else:
        print(f"Round 2 attack: Python port of /challenge/l2.js -> {BASE_URL}")
        report(run())
