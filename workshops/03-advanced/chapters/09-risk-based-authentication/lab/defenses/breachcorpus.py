"""
Local k-anonymity breach corpus (shared helper, not a student exercise).

A fully offline mirror of the Have I Been Pwned "Pwned Passwords" range API. The corpus is the
lab's own wordlist (data/wordlists/passwords_top.txt: the 30 passwords that users 000-029 of
the seed reuse), hashed with SHA-1 and bucketed by the first five hex characters of the hash, the
way the real API answers `GET /range/<5 hex>`: lines of `SUFFIX:COUNT`.

Checking a password reveals nothing about it: you send (or here, read) only the five-character
prefix and compare the 35-character suffix locally. In production you either call the real API
(HIBP, k-anonymity, free), or host the dataset yourself (the official PwnedPasswordsDownloader plus
a Bloom filter or a sorted file). This lab never calls it: the corpus is synthetic, offline, and
every lab round is deterministic.
"""

import hashlib
import os
from functools import lru_cache

WORDLIST = os.path.join(os.path.dirname(__file__), "..", "data", "wordlists", "passwords_top.txt")


@lru_cache(maxsize=1)
def _ranges():
    buckets = {}
    with open(WORDLIST) as f:
        for n, line in enumerate(f):
            pw = line.strip()
            if not pw or pw.startswith("#"):
                continue
            digest = hashlib.sha1(pw.encode("utf-8")).hexdigest().upper()
            # A deterministic, plausible count: the commonest passwords were seen the most.
            buckets.setdefault(digest[:5], {})[digest[5:]] = 2_000_000 // (n + 1)
    return buckets


def range_lookup(prefix):
    """What the range API returns for a 5-hex-character prefix: {suffix: count}."""
    return dict(_ranges().get(prefix.upper(), {}))


def pwned_count(password):
    """How many times `password` appears in the corpus (0 if absent)."""
    digest = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    return range_lookup(digest[:5]).get(digest[5:], 0)


def is_pwned(password):
    return pwned_count(password) > 0
