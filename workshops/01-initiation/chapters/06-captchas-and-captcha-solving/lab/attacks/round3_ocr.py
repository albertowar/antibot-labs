"""
Chapter 6 — Round 3 Attack: solve the image with a targeted solver (Section 6.4)

Objective: the answer is no longer in the cookie, so read the image. The
solver (attacks/ocr_solver.py) trains on the defender's own generator in a
few seconds, then solves each challenge in tens of milliseconds.

One attempt per challenge, one fresh session per voucher.

Expected results (see the instructor table in the README for measured values):
  - DEFENSE_LEVEL=2 (basic style)    → most of 20 attempts succeed
  - DEFENSE_LEVEL=3 (hardened style) → a few succeed

Run:
    python attacks/round3_ocr.py
    python attacks/round3_ocr.py --tesseract   # compare with generic OCR (needs the binary)
"""

import argparse
import io
import time

import httpx

from common import bot, new_challenge, redeem, require_local, summary, unlock
from labkit import BASE_URL
from ocr_solver import Solver

ATTEMPTS = 20


def tesseract_solve(png):
    """Generic OCR for comparison: no training, no knowledge of the generator."""
    import pytesseract
    from PIL import Image
    from ocr_solver import binarize
    from captcha_generator import CHARSET
    mask = binarize(Image.open(io.BytesIO(png)))
    img = Image.fromarray(((~mask) * 255).astype("uint8"))
    out = pytesseract.image_to_string(
        img, config=f"--psm 7 -c tessedit_char_whitelist={CHARSET}")
    return out.strip().replace(" ", "")


def run(solver=None, use_tesseract=False):
    """Run the attack; return a summary dict (used by tools/checkpoint.py)."""
    require_local()
    style = httpx.get(f"{BASE_URL}/lab/status", timeout=5).json()["style"]
    if solver is None and not use_tesseract:
        solver = Solver(style).train()
    hits, solve_ms, reasons = 0, [], {}
    for _ in range(ATTEMPTS):
        c = bot()
        unlock(c)
        cid, png = new_challenge(c)
        if cid is None:
            return summary("round3_ocr", 0, 0, style=style, note="no CAPTCHA at this level")
        start = time.perf_counter()
        guess = tesseract_solve(png) if use_tesseract else solver.solve(png)
        solve_ms.append((time.perf_counter() - start) * 1000)
        status, body = redeem(c, cid, guess)
        hits += status == 200
        if status != 200:
            reasons[body.get("error")] = reasons.get(body.get("error"), 0) + 1
    return summary("round3_ocr", ATTEMPTS, hits, style=style,
                   solve_ms=sum(solve_ms) / len(solve_ms), reasons=reasons,
                   train_s=getattr(solver, "train_seconds", 0.0))


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--tesseract", action="store_true")
    args = p.parse_args()
    s = run(use_tesseract=args.tesseract)
    print(f"=== Round 3: {'Tesseract' if args.tesseract else 'targeted solver'} "
          f"vs the {s['style']} style ===")
    if not s["attempts"]:
        print(f"  {s['note']}")
    else:
        if s.get("train_s"):
            print(f"  trained in {s['train_s']:.1f} s on the defender's own generator")
        print(f"  vouchers: {s['successes']}/{s['attempts']} "
              f"({100 * s['successes'] / s['attempts']:.0f}%) · {s['solve_ms']:.0f} ms per solve")
        for reason, n in s["reasons"].items():
            print(f"  rejected ×{n}: {reason}")
