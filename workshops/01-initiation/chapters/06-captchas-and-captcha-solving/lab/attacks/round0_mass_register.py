"""
Chapter 6 — Round 0 Attack: mass registration, no CAPTCHA (Section 6.6)

Objective: create 20 fake accounts as fast as possible from one IP. This
is the baseline every later round is measured against.

Expected results:
  - DEFENSE_LEVEL=0                  → 20/20 accounts created
  - DEFENSE_LEVEL=1, shipped verifier → 20/20 (a missing token is "fine")
  - DEFENSE_LEVEL≥1, fixed verifier   → 0/20  ("missing token")

Run:
    python attacks/round0_mass_register.py
"""

import time

from common import bot, require_local, summary

ATTEMPTS = 20


def run():
    """Run the attack; return a summary dict (used by tools/checkpoint.py)."""
    require_local()
    c = bot()
    start, created, reasons = time.perf_counter(), 0, {}
    for i in range(ATTEMPTS):
        r = c.post("/register", data={"email": f"bot{i}-{time.time_ns()}@example.test",
                                      "password": "hunter2"})
        if r.status_code == 201:
            created += 1
        else:
            reason = r.json().get("error", r.status_code)
            reasons[reason] = reasons.get(reason, 0) + 1
    return summary("round0_mass_register", ATTEMPTS, created,
                   seconds=time.perf_counter() - start, reasons=reasons)


if __name__ == "__main__":
    s = run()
    print("=== Round 0: mass registration ===")
    print(f"  accounts created: {s['successes']}/{s['attempts']} in {s['seconds']:.2f} s")
    for reason, n in s["reasons"].items():
        print(f"  rejected ×{n}: {reason}")
