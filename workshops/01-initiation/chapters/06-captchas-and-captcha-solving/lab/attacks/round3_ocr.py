"""
Chapter 6, Round 3 attack: solve the image with a targeted solver (section 6.4).

Objective: the answer is no longer in the cookie, so read the image. The solver
(attacks/ocr_solver.py) trains on the defender's own generator in a few seconds, then solves
each challenge in tens of milliseconds.

One attempt per challenge, one fresh session per voucher.

Expected (the expected-results table in the README has the measured values):
  DEFENSE_LEVEL=2 (basic style)     most of 20 attempts succeed
  DEFENSE_LEVEL=3 (hardened style)  a few succeed

    python attacks/round3_ocr.py
    python attacks/round3_ocr.py --tesseract   # compare with generic OCR (needs the binary)
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tools"))
import labclient  # noqa: E402,F401  (the localhost guard runs on import)
import captcha_kit as ck  # noqa: E402
import argparse  # noqa: E402
import io  # noqa: E402
import time  # noqa: E402

from ocr_solver import Solver, binarize  # noqa: E402

ATTEMPTS = 20


def tesseract_solve(png):
    """Generic OCR for comparison: no training, no knowledge of the generator."""
    import pytesseract
    from PIL import Image
    from defenses.captcha_generator import CHARSET
    mask = binarize(Image.open(io.BytesIO(png)))
    img = Image.fromarray(((~mask) * 255).astype("uint8"))
    out = pytesseract.image_to_string(img, config=f"--psm 7 -c tessedit_char_whitelist={CHARSET}")
    return out.strip().replace(" ", "")


def run(use_tesseract=False):
    style = ck.image_style()
    solver = None if use_tesseract else Solver(style).train()
    solve_ms, hits, why = [], 0, {}

    def solve(png, _cid):
        start = time.perf_counter()
        guess = tesseract_solve(png) if use_tesseract else solver.solve(png)
        solve_ms.append((time.perf_counter() - start) * 1000)
        return guess

    ip = ck.bot("ocr").ip
    for _ in range(ATTEMPTS):
        voucher, how = ck.claim(ck.bot("ocr", ip=ip), solve)
        hits += bool(voucher)
        if not voucher:
            why[how] = why.get(how, 0) + 1
    return ck.report("round3_ocr" + ("_tesseract" if use_tesseract else ""), ATTEMPTS, hits, style=style,
                     solve_ms=round(sum(solve_ms) / max(1, len(solve_ms)), 1), failed=why,
                     reasons=ck.reasons("bot:ocr", "captcha_reason"), train_s=round(getattr(solver, "train_seconds", 0.0), 1))


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--tesseract", action="store_true")
    args = p.parse_args()
    s = run(use_tesseract=args.tesseract)
    print(f"=== Round 3: {'Tesseract' if args.tesseract else 'targeted solver'} vs the {s['style']} style ===")
    if s["train_s"]:
        print(f"  trained in {s['train_s']} s on the defender's own generator")
    print(f"  vouchers: {s['succeeded']}/{s['attempted']} ({100 * s['succeeded'] / s['attempted']:.0f}%) · {s['solve_ms']} ms per solve")
    for reason, n in s["reasons"].items():
        print(f"  refused x{n}: {reason}")
    ck.emit(s)
