"""
Chapter 6 — Round 4 Attack A: retry until the solver gets lucky (Section 6.5)

Objective: beat the hardened style without a better solver. If one guess
in ten is right, a bot that asks for fresh challenges forever gets every
voucher it wants; each try costs milliseconds and nothing else.

Goal: 10 vouchers, at most MAX_TRIES challenges in total.

Expected results:
  - DEFENSE_LEVEL=3 → 10/10 vouchers, after many tries
  - DEFENSE_LEVEL=4, fixed signals → ~0: every correct solve is far
    faster than a person can read, and the failures pile up per IP

Run:
    python attacks/round4_retry_ocr.py
"""

import httpx

from common import bot, new_challenge, redeem, require_local, summary, unlock
from labkit import BASE_URL
from ocr_solver import Solver

GOAL, MAX_TRIES = 10, 300


def run(solver=None):
    """Run the attack; return a summary dict (used by tools/checkpoint.py)."""
    require_local()
    style = httpx.get(f"{BASE_URL}/lab/status", timeout=5).json()["style"]
    solver = solver or Solver(style).train()
    c = bot()
    ip = c.headers["X-Lab-Client-IP"]
    vouchers, tries, reasons = 0, 0, {}
    while vouchers < GOAL and tries < MAX_TRIES:
        c = bot(ip)                       # fresh session, same IP
        unlock(c)
        cid, png = new_challenge(c)
        if cid is None:
            break
        tries += 1
        status, body = redeem(c, cid, solver.solve(png))
        if status == 200:
            vouchers += 1
        else:
            reasons[body.get("error")] = reasons.get(body.get("error"), 0) + 1
    return summary("round4_retry_ocr", tries, vouchers, goal=GOAL, style=style,
                   reasons=reasons)


if __name__ == "__main__":
    s = run()
    print(f"=== Round 4A: retry the solver vs the {s['style']} style ===")
    print(f"  vouchers: {s['successes']}/{s['goal']} after {s['attempts']} challenges")
    for reason, n in sorted(s["reasons"].items(), key=lambda kv: -kv[1]):
        print(f"  rejected ×{n}: {reason}")
