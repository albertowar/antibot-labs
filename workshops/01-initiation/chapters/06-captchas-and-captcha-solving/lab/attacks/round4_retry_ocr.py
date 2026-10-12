"""
Chapter 6, Round 4 attack A: retry until the solver gets lucky (section 6.5).

Objective: beat the hardened style without a better solver. If one guess in ten is right, a bot
that asks for fresh challenges forever gets every voucher it wants; each try costs milliseconds
and nothing else.

Goal: 10 vouchers, at most MAX_TRIES challenges in total (a fresh session per try, one IP).

Expected:
  DEFENSE_LEVEL=3                    10/10 vouchers, after many tries
  DEFENSE_LEVEL=4, fixed signals     ~0: every correct solve is far faster than a person can
                                     read, and the failures pile up per IP

    python attacks/round4_retry_ocr.py
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tools"))
import labclient  # noqa: E402,F401  (the localhost guard runs on import)
import captcha_kit as ck  # noqa: E402
from ocr_solver import Solver  # noqa: E402

GOAL, MAX_TRIES = 10, 300


def run():
    style = ck.image_style()
    solver = Solver(style).train()
    ip = ck.bot("ocr_retry").ip
    vouchers, tries, why = 0, 0, {}
    while vouchers < GOAL and tries < MAX_TRIES:
        tries += 1
        voucher, how = ck.claim(ck.bot("ocr_retry", ip=ip), lambda png, _cid: solver.solve(png))
        vouchers += bool(voucher)
        if not voucher:
            why[how] = why.get(how, 0) + 1
    return ck.report("round4_retry_ocr", GOAL, vouchers, tries=tries, style=style, failed=why,
                     reasons=ck.reasons("bot:ocr_retry", "captcha_reason"))


if __name__ == "__main__":
    s = run()
    print(f"=== Round 4A: retry the solver vs the {s['style']} style ===")
    print(f"  vouchers: {s['succeeded']}/{s['attempted']} after {s['tries']} challenges")
    for reason, n in sorted(s["reasons"].items(), key=lambda kv: -kv[1])[:6]:
        print(f"  refused x{n}: {reason}")
    ck.emit(s)
