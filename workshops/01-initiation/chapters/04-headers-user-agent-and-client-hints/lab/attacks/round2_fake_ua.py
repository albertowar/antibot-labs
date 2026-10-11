"""
Chapter 4, Round 2 attack: borrow a Chrome User-Agent.

Objective: the store blocks python-requests by its User-Agent, so the attacker pastes a Chrome string
and changes nothing else: the other defaults (`Accept: */*`, no Accept-Language, no Sec-Fetch-*) stay.

Expected:
  DEFENSE_LEVEL=1     5/5 pages: the UA now parses as Chrome 153 on Windows
  DEFENSE_LEVEL>=2    0/5: headers:missing_accept_language, headers:no_sec_fetch, headers:accept_any_on_navigation

    python attacks/round2_fake_ua.py
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tools"))
from headers_client import CHROME_UA, Tally, bot, fetch_catalog, finish, requests_defaults  # noqa: E402


def run():
    headers = [("User-Agent", CHROME_UA)] + [(k, v) for k, v in requests_defaults() if k != "User-Agent"]
    return fetch_catalog(bot("fake-ua", 2), headers, Tally("round2_fake_ua")).result()


if __name__ == "__main__":
    print("=== Round 2: Chrome User-Agent, everything else default ===")
    finish(run())
