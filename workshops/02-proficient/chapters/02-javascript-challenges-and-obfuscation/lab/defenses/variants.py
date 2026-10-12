"""
Chapter 2 — Challenge variants: op chains, rendering and verification (2.2, 2.4)

A challenge answer is f(nonce): an FNV-style fold of the nonce through a short
chain of 32-bit operations. This module

  - defines the FIXED chain used at Round 2 (readable, so it can be ported),
  - generates RANDOM chains for the Round 3+ variant pool (polymorphism),
  - renders defenses/challenge_template.js for a chain,
  - re-computes the expected answer server-side, without running any JS.

Trade-offs:
  - f is deliberately cheap (microseconds). It is NOT proof of work (that's
    W1 Ch6). Its job is to force the client to run *our current* code, not to
    burn CPU.
  - Polymorphism only helps while the attacker has to re-read each variant by
    hand. A pool of 20 static files can be downloaded and machine-extracted
    (see the Babel/webcrack bonus). Rotation frequency is the real lever, and
    every rotation is a deploy you have to test across browsers.
  - The server computes answers in Python. JS numbers are doubles, so every op
    in the template ends in `>>> 0` or uses Math.imul to stay in uint32 and
    match Python bit for bit. Get this wrong and you block every real user:
    the companion repo's old djb2 challenge did exactly that.

Run this file to see a sample variant and its answer:
    python defenses/variants.py
"""

import os
import random

MASK = 0xFFFFFFFF
FNV_OFFSET = 0x811C9DC5
NATIVE_OK, NATIVE_BAD = 0x5BD1E995, 0x0BAD0BAD
ENGINE_V8, ENGINE_OTHER = 1, 2

TEMPLATE_PATH = os.path.join(os.path.dirname(__file__), "challenge_template.js")

# Round 2: one fixed chain for everybody. Readable, portable, and that's the point.
L2_CHAIN = [("mul", 0x01000193), ("rotl", 5), ("add", 0x9E3779B9)]
L2_PROBE = (120, 4, 1)          # width, padding, border (unused at L2: env is off)

OPS = ("xor", "add", "mul", "rotl", "xorshift")


def rotl(h, r):
    return ((h << r) | (h >> (32 - r))) & MASK


def apply_op(h, op, k):
    if op == "xor":
        return h ^ k
    if op == "add":
        return (h + k) & MASK
    if op == "mul":
        return (h * k) & MASK
    if op == "rotl":
        return rotl(h, k)
    if op == "xorshift":
        return h ^ (h >> k)
    raise ValueError(op)


def step(h, c, chain):
    h = (h ^ c) & MASK
    for op, k in chain:
        h = apply_op(h, op, k)
    return h


def probe_width(probe):
    width, padding, border = probe
    return width + 2 * padding + 2 * border


def expected_answer(nonce, chain, env=None):
    """The answer a correct client returns. `env` is (layout_px, native_ok, engine) or None."""
    h = FNV_OFFSET
    for ch in nonce:
        h = step(h, ord(ch), chain)
    if env is not None:
        layout_px, native_ok, engine = env
        h = step(h, layout_px, chain)
        h = step(h, NATIVE_OK if native_ok else NATIVE_BAD, chain)
        h = step(h, engine, chain)
    return f"{h:08x}"


def random_chain(rng):
    """4-7 ops. mul constants are odd so the step stays a bijection on uint32."""
    chain = []
    for _ in range(rng.randint(4, 7)):
        op = rng.choice(OPS)
        if op in ("rotl", "xorshift"):
            k = rng.randint(1, 31) if op == "rotl" else rng.randint(7, 17)
        elif op == "mul":
            k = rng.getrandbits(32) | 1
        else:
            k = rng.getrandbits(32)
        chain.append((op, k))
    return chain


def random_probe(rng):
    return (rng.randint(60, 240), rng.randint(0, 12), rng.randint(0, 4))


def op_to_js(op, k):
    if op == "xor":
        return f"h = (h ^ 0x{k:08x}) >>> 0;"
    if op == "add":
        return f"h = (h + 0x{k:08x}) >>> 0;"
    if op == "mul":
        return f"h = Math.imul(h, 0x{k:08x}) >>> 0;"
    if op == "rotl":
        return f"h = ((h << {k}) | (h >>> {32 - k})) >>> 0;"
    if op == "xorshift":
        return f"h = (h ^ (h >>> {k})) >>> 0;"
    raise ValueError(op)


def render(chain, probe):
    """Fill the template for one chain and probe. Returns readable JavaScript."""
    with open(TEMPLATE_PATH) as f:
        source = f.read()
    ops = "\n    ".join(op_to_js(op, k) for op, k in chain)
    width, padding, border = probe
    return (source.replace("__OPS__", ops)
                  .replace("__PROBE_W__", str(width))
                  .replace("__PROBE_P__", str(padding))
                  .replace("__PROBE_B__", str(border)))


if __name__ == "__main__":
    rng = random.Random(7)
    chain, probe = random_chain(rng), random_probe(rng)
    print("Sample variant chain:", chain)
    print("Probe box:", probe, "-> offsetWidth", probe_width(probe))
    print("Answer for nonce 'abc123' (env off):", expected_answer("abc123", chain))
    print("Answer for nonce 'abc123' (real Chrome):",
          expected_answer("abc123", chain, (probe_width(probe), True, ENGINE_V8)))
    print("\n--- rendered step() ---")
    js = render(chain, probe)
    start = js.index("function step")
    print(js[start:js.index("function isNative")])
