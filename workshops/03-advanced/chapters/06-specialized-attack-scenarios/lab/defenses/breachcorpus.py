"""k-anonymity breach-password lookup — shared helper, not student-edited.

The credential-stuffing economy runs on *known* passwords: combo lists are breach
dumps. So the signature a stuffer cannot hide is that its hits are, by definition,
breached passwords. We check a submitted password against a breach corpus the way
Have I Been Pwned's Pwned Passwords API does it, with k-anonymity: hash the
password with SHA-1, send only the first 5 hex characters, and look for the
remaining suffix in the returned bucket. The full password never leaves the box.

Default: an offline fixture under data/breach_ranges/ seeded by tools/seed.py, so
the lab runs with no network. Set HIBP_LIVE=1 to query the real range API instead
(the one and only outbound call the lab ever makes; it is still k-anonymous).
"""

from __future__ import annotations

import hashlib
import os


class BreachCorpus:
    def __init__(self, ranges_dir: str, live: bool = False):
        self.ranges_dir = ranges_dir
        self.live = live

    def _suffixes(self, prefix: str) -> dict:
        """Return {suffix: count} for a 5-char SHA-1 prefix."""
        if self.live:
            import httpx
            resp = httpx.get(f"https://api.pwnedpasswords.com/range/{prefix}", timeout=5.0)
            text = resp.text
        else:
            path = os.path.join(self.ranges_dir, f"{prefix}.txt")
            if not os.path.exists(path):
                return {}
            with open(path) as fh:
                text = fh.read()
        out = {}
        for line in text.splitlines():
            if ":" in line:
                suf, cnt = line.strip().split(":", 1)
                out[suf.upper()] = int(cnt)
        return out

    def count(self, password: str) -> int:
        """How many breaches this password appears in (0 = not found)."""
        sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
        prefix, suffix = sha1[:5], sha1[5:]
        return self._suffixes(prefix).get(suffix, 0)

    def is_breached(self, password: str) -> bool:
        return self.count(password) > 0
