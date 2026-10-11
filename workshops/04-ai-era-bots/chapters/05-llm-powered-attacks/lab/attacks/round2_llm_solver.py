"""Round 2 attack — an LLM/VLM challenge solver registering accounts.

The gate serves a text puzzle or a 3x3 image grid. A scripted solver (``--ocr``)
handles only the arithmetic puzzles it was coded for and guesses the tiles, so
the gate holds it. The LLM solver (default) answers every text puzzle by reasoning
and "reads" the tiles with a vision model, then brute-forces any proof-of-work the
token carries. The puzzle is no longer the obstacle.

On the mock backend the "vision" step reads a label the gate embeds in each tile
PNG — a stand-in for a model's eyes, documented in tools/llm.py. Point LLM_URL at
a local vision model to make it see pixels.

Targets the local store only. Accounts, devices and IPs are synthetic.

    python attacks/round2_llm_solver.py               # LLM/VLM solver (beats the gate)
    python attacks/round2_llm_solver.py --ocr         # scripted solver (beaten already)
    python attacks/round2_llm_solver.py --mode text   # force the text puzzle
"""

from __future__ import annotations

import argparse
import base64
import os
import sys

import requests

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))
from _common import BASE_URL, DATACENTER, headers, require_local  # noqa: E402
from defenses.challenge_gate import pow_solve  # noqa: E402
from tools.llm import LLM, reset_usage, usage  # noqa: E402

N_ACCOUNTS = 40


def _solve(llm, chal, ocr):
    mode, prompt = chal["mode"], chal["prompt"]
    if mode == "text":
        if ocr:  # scripted: only arithmetic, fails lexicon/reverse/count/letter
            import re
            m = re.search(r"what is (\d+)\s*([+\-*])\s*(\d+)", prompt, re.I)
            if m:
                a, op, b = int(m.group(1)), m.group(2), int(m.group(3))
                return str(a + b if op == "+" else a - b if op == "-" else a * b)
            return "0"
        return llm.chat("solve_text", "You solve small puzzles. Reply with only the answer.", prompt).text
    tiles = [base64.b64decode(t) for t in chal["tiles"]]
    if ocr:   # scripted: no real vision, guesses the middle tile
        return "5"
    return llm.chat("solve_image", "You identify shapes in image tiles.", prompt, images=tiles).text


def run(base=BASE_URL, ocr=False, mode="image", n=N_ACCOUNTS, n_devices=3):
    require_local(base)
    llm = LLM()
    reset_usage()
    created = 0
    for i in range(n):
        fp, ip = f"solver-fp-{i % n_devices}", DATACENTER[i % n_devices]
        h = headers("bot", ip, fp=fp, session=f"solver-sess-{i}")
        email = f"solver_{i:04d}@mail.example"
        r = requests.post(f"{base}/register",
                          json={"email": email, "password": "Reg-" + "x" * 8, "mode": mode},
                          headers=h, timeout=15).json()
        if r.get("outcome") == "allow":          # no challenge served
            created += 1
            continue
        chal = r.get("challenge")
        if not chal:                              # blocked before a puzzle
            continue
        answer = _solve(llm, chal, ocr)
        nonce = pow_solve(chal["token"], chal["pow_bits"]) if chal.get("pow_bits") else ""
        r2 = requests.post(f"{base}/register",
                           json={"email": email, "password": "Reg-" + "x" * 8, "mode": mode,
                                 "challenge_token": chal["token"], "answer": answer, "nonce": nonce},
                           headers=h, timeout=15).json()
        if r2.get("outcome") == "allow":
            created += 1
    u = usage()
    per = (u["prompt_tokens"] + u["completion_tokens"]) / max(1, u["calls"])
    style = "scripted OCR" if ocr else f"LLM/VLM ({llm.backend})"
    print(f"[round2] {style} solver: {created}/{n} accounts created; "
          f"{u['calls']} model calls, ~{per:.0f} tokens/solve, {u['ms']:.0f} ms total.")
    return created


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--ocr", action="store_true", help="scripted solver (already beaten)")
    ap.add_argument("--mode", choices=["image", "text"], default="image")
    ap.add_argument("--url", default=BASE_URL)
    a = ap.parse_args()
    run(base=a.url, ocr=a.ocr, mode=a.mode)
