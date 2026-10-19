"""Round 2, pre-wired: the challenge gate (puzzles, tiles, tokens, proof-of-work).

This is the W1 Ch5 / Ch6 gate as the store had it: a text puzzle a script can't parse, a 3x3 image puzzle
an OCR solver can't read, a single-use token, and an optional hashcash proof-of-work bound to the token.
It is not student-edited. `demo_site/ext/llm_surfaces.py` registers it as the `puzzle` challenge type;
Round 2 shows an LLM/VLM solving all of it, and challenge_policy.py decides *who* gets it, *how
expensive* it is and *what a solve is worth*.

Puzzle kinds (text):  arithmetic, lexicon ("which of these is a fruit"), reverse, count, letter.  Image:
nine 72x72 tiles, each with one shape; "select all tiles containing a triangle". Every tile PNG carries a
``lab-label`` tEXt chunk with the shape and colour. That label is how the *mock* vision model "sees"; a
real model (``LLM_URL``) gets only the pixels. The label is a lab shortcut, not a weakness of real
CAPTCHAs, and a reminder that no secret belongs in the image you serve.

An accessible alternative is non-negotiable: ``?mode=text`` always yields a text
puzzle. Screen-reader users cannot solve the tiles (W1 Ch5).
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import random
import secrets
import time

from PIL import Image, ImageDraw
from PIL.PngImagePlugin import PngInfo

TOKEN_TTL_S = 300
SHAPES = ["circle", "square", "triangle"]
COLOURS = {"red": (220, 60, 60), "blue": (60, 90, 220), "green": (50, 160, 80),
           "amber": (230, 170, 30)}
LEXICON = {
    "fruit": ["apple", "pear", "banana", "cherry", "mango", "plum", "grape", "lemon"],
    "animal": ["otter", "heron", "badger", "lynx", "goat", "trout", "wren", "moose"],
    "colour": ["red", "blue", "green", "amber", "violet", "teal", "ochre", "ivory"],
    "tool": ["hammer", "wrench", "chisel", "pliers", "saw", "drill", "trowel", "awl"],
}
WORDS = ["planet", "harbor", "copper", "saddle", "meadow", "lantern", "velvet", "orchard"]


# --- puzzle generation -------------------------------------------------------------

def text_puzzle(rng: random.Random):
    kind = rng.choice(["arithmetic", "lexicon", "reverse", "count", "letter"])
    if kind == "arithmetic":
        a, b = rng.randint(2, 19), rng.randint(2, 19)
        op = rng.choice(["+", "-", "*"])
        ans = a + b if op == "+" else a - b if op == "-" else a * b
        return f"What is {a} {op} {b}?", str(ans)
    if kind == "lexicon":
        cat = rng.choice(list(LEXICON))
        answer = rng.choice(LEXICON[cat])
        others = [rng.choice(LEXICON[c]) for c in LEXICON if c != cat]
        opts = [answer] + rng.sample(others, 2)
        rng.shuffle(opts)
        article = "an" if cat[0] in "aeiou" else "a"
        return f"Which of these is {article} {cat}: {', '.join(opts)}?", answer
    w = rng.choice(WORDS)
    if kind == "reverse":
        return f"Type the word '{w}' backwards.", w[::-1]
    if kind == "count":
        return f"How many letters are in '{w}'?", str(len(w))
    which = rng.choice(["first", "last"])
    return f"What is the {which} letter of '{w}'?", (w[0] if which == "first" else w[-1])


def _tile(shape: str, colour: str, rng: random.Random) -> bytes:
    img = Image.new("RGB", (72, 72), (245, 245, 240))
    d = ImageDraw.Draw(img)
    rgb = COLOURS[colour]
    cx, cy, r = 36 + rng.randint(-6, 6), 36 + rng.randint(-6, 6), rng.randint(16, 24)
    if shape == "circle":
        d.ellipse((cx - r, cy - r, cx + r, cy + r), fill=rgb)
    elif shape == "square":
        d.rectangle((cx - r, cy - r, cx + r, cy + r), fill=rgb)
    else:
        d.polygon([(cx, cy - r), (cx - r, cy + r), (cx + r, cy + r)], fill=rgb)
    for _ in range(40):  # speckle, so a byte-exact lookup table is not enough
        d.point((rng.randint(0, 71), rng.randint(0, 71)), fill=(200, 200, 195))
    meta = PngInfo()
    meta.add_text("lab-label", f"{shape},{colour}")
    buf = io.BytesIO()
    img.save(buf, "PNG", pnginfo=meta)
    return buf.getvalue()


def image_puzzle(rng: random.Random):
    target = rng.choice(SHAPES)
    n_target = rng.randint(2, 4)
    shapes = [target] * n_target + [rng.choice([s for s in SHAPES if s != target])
                                    for _ in range(9 - n_target)]
    rng.shuffle(shapes)
    tiles = [_tile(s, rng.choice(list(COLOURS)), rng) for s in shapes]
    answer = ",".join(str(i + 1) for i, s in enumerate(shapes) if s == target)
    return f"Select all tiles containing a {target}. Reply with the tile numbers (1-9), comma-separated.", answer, tiles


# --- issue / verify ------------------------------------------------------------------

def issue(rds, mode: str, pow_bits: int = 0) -> dict:
    rng = random.Random(secrets.randbits(64))
    token = secrets.token_urlsafe(16)
    if mode == "text":
        prompt, answer = text_puzzle(rng)
        tiles = []
    else:
        prompt, answer, tiles = image_puzzle(rng)
    rds.setex(f"lab:llm:chal:{token}", TOKEN_TTL_S, json.dumps(
        {"answer": answer, "issued": time.time(), "bits": pow_bits, "mode": mode}))
    return {"token": token, "mode": mode, "prompt": prompt, "pow_bits": pow_bits,
            "tiles": [base64.b64encode(t).decode() for t in tiles]}


def normalize(ans: str) -> str:
    return "".join(ch for ch in ans.lower() if ch.isalnum() or ch == ",").strip(",")


def verify(rds, token: str, answer: str, nonce: str):
    """Returns (ok, reason, solve_ms). Single use: the token is deleted either way."""
    raw = rds.get(f"lab:llm:chal:{token}")
    if raw is None:
        return False, "unknown or expired challenge token", 0.0
    rds.delete(f"lab:llm:chal:{token}")
    rec = json.loads(raw)
    solve_ms = (time.time() - rec["issued"]) * 1000
    if rec["bits"] and not pow_ok(token, nonce or "", rec["bits"]):
        return False, f"proof-of-work missing or invalid ({rec['bits']} bits)", solve_ms
    if normalize(answer or "") != normalize(rec["answer"]):
        return False, "wrong answer", solve_ms
    return True, f"solved ({rec['mode']}) in {solve_ms:.0f} ms", solve_ms


# --- proof of work (W1 Ch6) --------------------------------------------------------

def pow_ok(token: str, nonce: str, bits: int) -> bool:
    h = hashlib.sha256(f"{token}:{nonce}".encode()).digest()
    value = int.from_bytes(h[:8], "big")
    return value >> (64 - bits) == 0


def pow_solve(token: str, bits: int) -> str:
    """Attacker-side helper (also used by the human simulator): brute-force a nonce."""
    n = 0
    while not pow_ok(token, str(n), bits):
        n += 1
    return str(n)
