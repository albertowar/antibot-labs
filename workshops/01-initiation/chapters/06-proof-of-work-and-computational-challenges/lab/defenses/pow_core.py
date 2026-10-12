"""
Chapter 6 — The puzzle itself (Sections 6.2 and 6.7)

Every PoW scheme in this lab uses the same hashcash-style puzzle:

    find a counter c such that SHA-256(f"{nonce}:{c}") starts with
    `bits` zero bits

Both sides import this module:

  - the server calls `meets_difficulty()` to verify one hash (microseconds);
  - attackers and the legit-traffic simulator call `solve()` to brute-force
    a counter (about 2**bits hashes on average).

That gap, one hash to verify vs. ~2**bits hashes to solve, is the whole
idea. Everything else in this chapter is about who pays for those hashes
and how often.

Trade-offs worth knowing:

  - Each extra bit doubles the *expected* work. The *actual* work is
    geometric: p50 ≈ 0.69 × 2**bits, p95 ≈ 3 × 2**bits. Some users get
    unlucky, so plan your latency budget for p95, not the mean.
  - SHA-256 is cheap on GPUs and ASICs (billions of hashes per second), so
    the attacker's hardware can be far faster than your user's phone.
    Memory-hard functions (Argon2id, scrypt, Equi-X) shrink that gap; see
    the bonus challenge in lab/README.md.

Run the self-test:
    python defenses/pow_core.py
"""

from __future__ import annotations

import hashlib
import math
import time

MAX_BITS = 32  # anything above this would take hours; the server rejects it


def digest(nonce: str, counter: int | str) -> bytes:
    """The hash a client must make "small": SHA-256 of 'nonce:counter'."""
    return hashlib.sha256(f"{nonce}:{counter}".encode()).digest()


def leading_zero_bits(d: bytes) -> int:
    """Count the leading zero bits of a digest."""
    value = int.from_bytes(d, "big")
    return len(d) * 8 - value.bit_length()


def meets_difficulty(d: bytes, bits: int) -> bool:
    """True if the digest starts with at least `bits` zero bits.

    Note that bits=0 accepts *every* digest. If a client can choose `bits`,
    the puzzle is free. Round 1 exploits exactly that.
    """
    return leading_zero_bits(d) >= bits


def expected_hashes(bits: int) -> int:
    """Mean number of hashes to find a solution at this difficulty."""
    return 2 ** bits


def hashes_at_percentile(bits: int, p: float) -> int:
    """Hashes needed to have solved with probability p (geometric distribution)."""
    return math.ceil(math.log(1 - p) / math.log(1 - 2 ** -bits))


def solve(nonce: str, bits: int, start: int = 0, step: int = 1,
          max_hashes: int | None = None, stop=None) -> tuple[int | None, int]:
    """Brute-force a counter. Returns (counter or None, hashes tried).

    `start`/`step` let several processes split the search space
    (worker i of n tries i, i+n, i+2n, ...). `max_hashes` gives up early,
    which is how the legit-traffic simulator models a user who abandons.
    `stop` is an optional multiprocessing.Event checked every 4096 hashes.
    """
    prefix = hashlib.sha256(f"{nonce}:".encode())  # hash the prefix once, copy per try
    shift = 32 - min(bits, 32)  # fast path: look at the first 4 bytes only
    counter, tried = start, 0
    while max_hashes is None or tried < max_hashes:
        h = prefix.copy()
        h.update(str(counter).encode())
        tried += 1
        if int.from_bytes(h.digest()[:4], "big") >> shift == 0:
            return counter, tried
        counter += step
        if stop is not None and tried % 4096 == 0 and stop.is_set():
            break
    return None, tried


def hash_rate(seconds: float = 1.0) -> float:
    """Measure this machine's single-core rate in hashes per second."""
    prefix = hashlib.sha256(b"benchmark:")
    tried, deadline = 0, time.perf_counter() + seconds
    started = time.perf_counter()
    while time.perf_counter() < deadline:
        for counter in range(tried, tried + 10_000):
            h = prefix.copy()
            h.update(str(counter).encode())
            int.from_bytes(h.digest()[:4], "big") >> 12 == 0
        tried += 10_000
    return tried / (time.perf_counter() - started)


# Shared with demo_site/static/pow-worker.js: both must agree on these.
TEST_VECTORS = [
    # (nonce, counter, sha256 hex of "nonce:counter")
    ("abc", 0, "5f36efce86f68877cee18fda5637abb2a1bb409f4326cc741fdf13200aa26980"),
    ("a-much-longer-nonce-that-spans-two-sha256-blocks-0123456789abcdef", 42,
     "a1420cf5fe82e56a598a50f39d3c266ce78fd87b1c0ff86d9ee9a8dc51539700"),
]


def _self_test():
    for nonce, counter, expected in TEST_VECTORS:
        assert digest(nonce, counter).hex() == expected, (nonce, counter)
    print(f"  {len(TEST_VECTORS)} SHA-256 test vectors match")
    assert meets_difficulty(b"\x00\x00\xff" + bytes(29), 16)
    assert not meets_difficulty(b"\x00\x01" + bytes(30), 16)
    assert meets_difficulty(b"\xff" * 32, 0), "bits=0 accepts anything"
    counter, tried = solve("self-test", 12)
    assert meets_difficulty(digest("self-test", counter), 12)
    print(f"  solved 12 bits in {tried:,} hashes (expected ~{expected_hashes(12):,})")
    print(f"  16 bits: p50 {hashes_at_percentile(16, .5):,} · "
          f"p95 {hashes_at_percentile(16, .95):,} hashes")
    print(f"  this core: {hash_rate(0.5) / 1e6:.2f} MH/s")
    print("✅ pow_core self-test passed")


if __name__ == "__main__":
    _self_test()
