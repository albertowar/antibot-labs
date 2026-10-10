"""Local k-anonymity breach corpus (shared helper, not a student exercise).

A fully offline mirror of the Have I Been Pwned "Pwned Passwords" range API. The
seed script hashes every breached password with SHA-1 and writes one file per
5-hex-character prefix under ``data/breach_ranges/``, each line ``SUFFIX:COUNT`` —
byte-for-byte the shape of the real API's response.

Checking a password reveals nothing about it: we read only the file named by its
first five hash characters and scan locally for the 35-character suffix. The real
API works the same way so the plaintext never leaves your server. In production
you either call that API or build a Bloom filter / self-host the dataset with the
official PwnedPasswordsDownloader; here the corpus is tiny and synthetic.
"""

from __future__ import annotations

import hashlib
import os

_RANGES = os.path.join(os.path.dirname(__file__), "..", "data", "breach_ranges")


def pwned_count(password: str) -> int:
    """Return how many times ``password`` appears in the corpus (0 if absent)."""
    digest = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = digest[:5], digest[5:]
    path = os.path.join(_RANGES, f"{prefix}.txt")
    try:
        with open(path) as fh:
            for line in fh:
                have_suffix, _, count = line.strip().partition(":")
                if have_suffix == suffix:
                    return int(count or 0)
    except FileNotFoundError:
        return 0
    return 0


def is_pwned(password: str) -> bool:
    return pwned_count(password) > 0
