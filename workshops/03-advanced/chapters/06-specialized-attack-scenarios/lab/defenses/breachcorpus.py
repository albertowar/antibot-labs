"""
Breach-password corpus (shared helper, finished): the Pwned Passwords range API, offline by default.

A stuffer only has passwords that already leaked, so a login that presents the CORRECT password
and a password that is in a breach corpus is stuffable by definition. The way to ask is
k-anonymity (Have I Been Pwned, Pwned Passwords): SHA-1 the password, send only the first five
hex characters, get back every `SUFFIX:COUNT` in that bucket, and compare the other 35 characters
locally. The password never leaves the box.

Default: an offline mirror of that API built from the lab's own wordlist (data/wordlists/
passwords_top.txt: the 30 passwords that users 000-029 of the seed reuse), bucketed the way the
real API answers `GET /range/<5 hex>`. Nothing leaves your machine and every round is deterministic.

HIBP_LIVE=1 asks the real range API instead (https://api.pwnedpasswords.com/range/<prefix>). It is
the only outbound call this lab can make, it is OFF by default, and it still sends only the five
hex characters. The lab's passwords are common ones, so the real corpus knows them too; leave it
off unless you want to see the production lookup.
"""

import hashlib
import os
from functools import lru_cache

WORDLIST = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "data", "wordlists", "passwords_top.txt")
LIVE_URL = "https://api.pwnedpasswords.com/range/"


def live():
    return os.environ.get("HIBP_LIVE") == "1"


@lru_cache(maxsize=1)
def _offline():
    buckets = {}
    with open(WORDLIST) as fh:
        for n, line in enumerate(fh):
            pw = line.strip()
            if not pw or pw.startswith("#"):
                continue
            digest = hashlib.sha1(pw.encode("utf-8")).hexdigest().upper()
            buckets.setdefault(digest[:5], {})[digest[5:]] = 2_000_000 // (n + 1)     # commonest = seen most
    return buckets


@lru_cache(maxsize=4096)
def _live(prefix):
    import requests
    resp = requests.get(LIVE_URL + prefix, headers={"Add-Padding": "true"}, timeout=5)
    resp.raise_for_status()
    out = {}
    for line in resp.text.splitlines():
        suffix, _, count = line.strip().partition(":")
        if suffix and count.isdigit() and int(count) > 0:         # Add-Padding rows carry a zero count
            out[suffix.upper()] = int(count)
    return out


def range_lookup(prefix):
    """What the range API returns for a 5-hex-character prefix: {suffix: count}."""
    prefix = prefix.upper()
    return dict(_live(prefix)) if live() else dict(_offline().get(prefix, {}))


def pwned_count(password):
    """How many times `password` appears in the corpus (0 = not there)."""
    digest = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    return range_lookup(digest[:5]).get(digest[5:], 0)


def is_pwned(password):
    return pwned_count(password) > 0
