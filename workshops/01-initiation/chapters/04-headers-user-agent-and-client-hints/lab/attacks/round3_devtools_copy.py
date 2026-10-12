"""
Chapter 4, Round 3 attack: replay a full browser header set.

Objective: the attacker copies a complete set of browser headers (the kind in countless scraping
tutorials, or "Copy as cURL" from DevTools) so every presence and Sec-Fetch check passes. The Referer
and Sec-Fetch-Site are even adjusted to the target.

What the attacker did not copy: the Client Hints (a Chrome UA with no `sec-ch-ua`), and the order.
A Python dict is written in the order the attacker typed it, which is not Chrome's.

Expected:
  DEFENSE_LEVEL=2     5/5 pages: every presence and Fetch Metadata check passes
  DEFENSE_LEVEL>=3    0/5: client_hints:hints_absent (30) + header_order:unlike_chromium (15)

    python attacks/round3_devtools_copy.py
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tools"))
from headers_client import BASE_URL, CHROME_UA, Tally, bot, fetch_catalog, finish  # noqa: E402

COPIED_HEADERS = [
    ("User-Agent", CHROME_UA),
    ("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"),
    ("Accept-Language", "en-US,en;q=0.9"),
    ("Accept-Encoding", "gzip, deflate"),
    ("Referer", f"{BASE_URL}/"),
    ("Sec-Fetch-Dest", "document"),
    ("Sec-Fetch-Mode", "navigate"),
    ("Sec-Fetch-Site", "same-origin"),
    ("Sec-Fetch-User", "?1"),
    ("Connection", "keep-alive"),
    ("Upgrade-Insecure-Requests", "1"),
]


def run():
    return fetch_catalog(bot("devtools-copy", 3), COPIED_HEADERS, Tally("round3_devtools_copy")).result()


if __name__ == "__main__":
    print("=== Round 3: full browser header set, copied ===")
    finish(run())
