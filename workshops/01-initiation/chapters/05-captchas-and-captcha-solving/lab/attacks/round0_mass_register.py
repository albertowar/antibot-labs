"""
Chapter 5, Round 0 attack: mass registration, no CAPTCHA (section 5.6).

Objective: create 20 fake accounts as fast as possible from one datacenter IP. This is the
baseline every later round is measured against.

Expected:
  DEFENSE_LEVEL=0                     20/20 accounts created
  DEFENSE_LEVEL=1, shipped verifier   20/20 (a missing token is "fine")
  DEFENSE_LEVEL>=1, fixed verifier    0/20  (turnstile_reason "missing token")

    python attacks/round0_mass_register.py
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tools"))
import labclient  # noqa: E402,F401  (the localhost guard runs on import)
import captcha_kit as ck  # noqa: E402

ATTEMPTS = 20


def run():
    import time
    c = ck.bot("mass_register")
    start, created = time.perf_counter(), 0
    for i in range(ATTEMPTS):
        r = ck.post_json(c, "/api/register", {"email": ck.new_email(f"bot{i}"), "password": "hunter2-hunter2", "name": "Bot"})
        created += r.status_code == 201
    return ck.report("round0_mass_register", ATTEMPTS, created, seconds=round(time.perf_counter() - start, 2),
                     reasons=ck.reasons(c.actor, "turnstile_reason"))


if __name__ == "__main__":
    s = run()
    print("=== Round 0: mass registration ===")
    print(f"  accounts created: {s['succeeded']}/{s['attempted']} in {s['seconds']} s")
    for reason, n in s["reasons"].items():
        print(f"  refused x{n}: {reason}")
    ck.emit(s)
