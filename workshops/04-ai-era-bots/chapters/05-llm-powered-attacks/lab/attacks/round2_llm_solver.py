"""Round 2 attack: an LLM/VLM challenge solver registering accounts.

The gate serves a text puzzle or a 3x3 image grid. A scripted solver (`--ocr`) handles only the arithmetic
puzzles it was coded for and guesses the tiles, so the gate holds it. The LLM solver (default) answers every
text puzzle by reasoning and "reads" the tiles with a vision model, then brute-forces any proof-of-work the
puzzle carries. The puzzle is no longer the obstacle.

Per account: POST /api/register; on a 403 `challenge_required`, solve the payload, POST /api/challenge/verify,
and retry the registration. Forty accounts, three devices, one datacenter.

On the mock backend the "vision" step reads a label the gate embeds in each tile PNG: a stand-in for a
model's eyes, documented in tools/llm.py. Point LLM_URL at a local vision model to make it see pixels.

    python attacks/round2_llm_solver.py               # LLM/VLM solver (beats the gate)
    python attacks/round2_llm_solver.py --ocr         # scripted solver (held already)
    python attacks/round2_llm_solver.py --mode text   # force the text puzzle

Targets the local store only. Accounts, devices and addresses are synthetic.
"""

import argparse
import base64
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from _common import JSON_HEADERS, SOLVER_POOL, bot, finish  # noqa: E402
from defenses.challenge_gate import pow_solve  # noqa: E402
from llm import LLM, reset_usage, usage  # noqa: E402

N_ACCOUNTS = 40


def _solve(llm, chal, ocr):
    mode, prompt = chal["mode"], chal["prompt"]
    if mode == "text":
        if ocr:   # scripted: only arithmetic, fails lexicon/reverse/count/letter
            m = re.search(r"what is (\d+)\s*([+\-*])\s*(\d+)", prompt, re.I)
            if m:
                a, op, b = int(m.group(1)), m.group(2), int(m.group(3))
                return str(a + b if op == "+" else a - b if op == "-" else a * b)
            return "0"
        return llm.chat("solve_text", "You solve small puzzles. Reply with only the answer.", prompt).text
    if ocr:       # scripted: no real vision, guesses the middle tile
        return "5"
    tiles = [base64.b64decode(t) for t in chal["tiles"]]
    return llm.chat("solve_image", "You identify shapes in image tiles.", prompt, images=tiles).text


def run(ocr=False, mode="image", n=N_ACCOUNTS, n_devices=3):
    llm = LLM()
    reset_usage()
    created = solved = served = 0
    for i in range(n):
        dev = i % n_devices
        c = bot(f"bot:solver:{i:02d}", SOLVER_POOL[dev], device=f"solver-device-{dev}")
        body = {"email": f"solver_{i:04d}@mail.example", "password": f"Solver-pass-{i:04d}", "mode": mode}
        r = c.post("/api/register", json=body, headers=JSON_HEADERS)
        if r.status_code == 201:                               # no puzzle served
            created += 1
            continue
        err = (r.json() or {}).get("error", {}) if r.headers.get("Content-Type", "").startswith("application/json") else {}
        if err.get("code") != "challenge_required":            # refused outright
            continue
        served += 1
        chal = err["payload"]
        answer = _solve(llm, chal, ocr)
        nonce = pow_solve(chal["token"], chal["pow_bits"]) if chal.get("pow_bits") else ""
        v = c.post("/api/challenge/verify", json={"type": "puzzle", "answer": {
            "token": chal["token"], "answer": answer, "nonce": nonce}}, headers=JSON_HEADERS)
        if v.status_code != 200:
            continue
        solved += 1
        r = c.post("/api/register", json=body, headers=JSON_HEADERS)       # retry with the clearance
        if r.status_code == 201:
            created += 1
    u = usage()
    per = (u["prompt_tokens"] + u["completion_tokens"]) / max(1, u["calls"])
    style = "scripted OCR" if ocr else f"LLM/VLM ({llm.backend})"
    print(f"[round2] {style} solver: {created}/{n} accounts created; {served} puzzles served, {solved} solved; "
          f"{u['calls']} model calls, ~{per:.0f} tokens/solve, {u['ms']:.0f} ms of model time.")
    return finish({"attempted": n, "succeeded": created, "served": served, "solved": solved,
                   "calls": u["calls"], "tokens_per_solve": round(per)})


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--ocr", action="store_true", help="scripted solver (held already)")
    ap.add_argument("--mode", choices=["image", "text"], default="image")
    a = ap.parse_args()
    run(ocr=a.ocr, mode=a.mode)
