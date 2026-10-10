"""Legitimate-traffic simulator — the other half of every scoreboard.

A defense that blocks bots is worthless if it also blocks your customers, so this
runs ~145 synthetic humans alongside each attack and records what the defenses did
*to them*. The cohorts are the ones that break naive controls in production:

  * returning        — strong password, known device/network (should sail through)
  * breached_returning — real password that happens to be breached (L3 step-up)
  * typo             — fat-fingered password (an expected failure, NOT a false positive)
  * cgnat            — many users behind ONE shared IP (naive per-IP limits punish them)
  * new_device       — a real user on a new device/network (L4 step-up)

Each user keeps its own cookie jar so a step-up can be completed with a real TOTP
code — which only a genuine account holder could produce. We separate *blocked*
(denied a session they deserved: throttle or an unsolved challenge) from *friction*
(an extra step they could and did complete). Typos are counted apart, because
rejecting a wrong password is correct behavior, not a false positive.
"""

from __future__ import annotations

import os
import sys
from collections import Counter

import httpx
import pyotp

sys.path.insert(0, os.path.dirname(__file__))
from _paths import DATA  # noqa: E402

BASE_URL = os.environ.get("DEMO_URL", "http://127.0.0.1:5000")


def _login(client, user, password):
    return client.post("/login", json={"email": user["email"], "password": password},
                       headers={"X-Lab-Actor": f"legit:{user['scenario']}",
                                "X-Lab-Client-IP": user["ip"],
                                "X-Lab-Device": user["did"],
                                "X-Client-Sig": user["sig"],
                                "User-Agent": "Mozilla/5.0 (lab-legit-user)"})


def _play(user) -> str:
    """Drive one user and return a terminal outcome label."""
    password = user["password"]
    if user["scenario"] == "typo":
        password = password + "X"  # a wrong password this attempt

    with httpx.Client(base_url=BASE_URL, timeout=10.0) as client:
        r = _login(client, user, password)
        status = r.json().get("status") if r.headers.get("content-type", "").startswith(
            "application/json") else None

        if r.status_code == 429:
            return "throttled"
        if status == "success":
            return "success"
        if status == "challenge":
            return "challenge"          # interactive challenge a human could pass, bot can't
        if status == "error":
            return "invalid"            # wrong credentials (typo) — expected
        if status == "step_up":
            if user.get("totp_secret"):
                token = pyotp.TOTP(user["totp_secret"]).now()
                v = client.post("/verify-otp", json={"token": token},
                                headers={"X-Lab-Actor": f"legit:{user['scenario']}"})
                if v.status_code == 200 and v.json().get("status") == "success":
                    return "success_stepup"
            return "stepup_failed"
    return "unknown"


def run() -> dict:
    import json
    with open(os.path.join(DATA, "legit_users.json")) as fh:
        users = json.load(fh)

    outcomes = Counter(_play(u) for u in users)

    # A real user is harmed when denied a session they deserved. A typo is not harm.
    blocked = outcomes["throttled"] + outcomes["challenge"] + outcomes["stepup_failed"]
    friction = outcomes["success_stepup"]
    got_in = outcomes["success"] + outcomes["success_stepup"]
    return {
        "total": len(users),
        "logged_in": got_in,
        "blocked_false_positive": blocked,
        "friction_stepup": friction,
        "typo_rejected": outcomes["invalid"],
        "breakdown": dict(outcomes),
    }


def main():
    r = run()
    print(f"legit: {r['logged_in']}/{r['total']} logged in | "
          f"{r['blocked_false_positive']} wrongly blocked | "
          f"{r['friction_stepup']} stepped up | {r['typo_rejected']} typos rejected")
    print("  breakdown:", r["breakdown"])


if __name__ == "__main__":
    main()
