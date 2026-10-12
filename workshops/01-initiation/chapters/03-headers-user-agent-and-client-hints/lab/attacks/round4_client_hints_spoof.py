"""
Chapter 3, Round 4 attack: consistent Client Hints, Chrome order, a real context.

Objective: the attacker now models a Chrome session instead of replaying one capture:
  - low-entropy Client Hints that agree with the UA (GREASE brand included)
  - headers written in Chromium's order
  - contextual Fetch Metadata: a navigation to / first, then the same-origin fetch() the page makes
  - a cookie jar, like a browser

What a static header template cannot do: react to the store's Accept-CH, which asks for the
high-entropy hints on every request that follows. Chrome obliges; this script does not.

Expected:
  DEFENSE_LEVEL=3     navigation 200, 5/5 pages
  DEFENSE_LEVEL=4     navigation 200 (the response carries Accept-CH), then 0/5:
                      accept_ch:ignored ("Accept-CH was offered but the client ignored it")

Set NEGOTIATE=1 to see the ten lines it takes to beat that (Bonus 1 in the README).

    python attacks/round4_client_hints_spoof.py
"""

import os
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tools"))
from headers_client import BASE_URL, CHROME_MAJOR, CHROME_UA, Tally, bot, fetch_catalog, finish  # noqa: E402

SEC_CH_UA = f'"Google Chrome";v="{CHROME_MAJOR}", "Not?A_Brand";v="8", "Chromium";v="{CHROME_MAJOR}"'

# Chromium's order for a top-level navigation. Host goes first; the cookie jar adds Cookie last.
NAVIGATION = [
    ("Connection", "keep-alive"),
    ("sec-ch-ua", SEC_CH_UA), ("sec-ch-ua-mobile", "?0"), ("sec-ch-ua-platform", '"Windows"'),
    ("Upgrade-Insecure-Requests", "1"), ("User-Agent", CHROME_UA),
    ("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8"),
    ("Sec-Fetch-Site", "none"), ("Sec-Fetch-Mode", "navigate"), ("Sec-Fetch-User", "?1"), ("Sec-Fetch-Dest", "document"),
    ("Accept-Encoding", "gzip, deflate"), ("Accept-Language", "en-US,en;q=0.9"),
]

# Chromium's order for a same-origin fetch() issued by the page
FETCH = [
    ("Connection", "keep-alive"),
    ("sec-ch-ua-platform", '"Windows"'), ("User-Agent", CHROME_UA), ("sec-ch-ua", SEC_CH_UA), ("sec-ch-ua-mobile", "?0"),
    ("Accept", "*/*"),
    ("Sec-Fetch-Site", "same-origin"), ("Sec-Fetch-Mode", "cors"), ("Sec-Fetch-Dest", "empty"),
    ("Referer", f"{BASE_URL}/"),
    ("Accept-Encoding", "gzip, deflate"), ("Accept-Language", "en-US,en;q=0.9"),
]

# What the bot would have to add once it reads Accept-CH (NEGOTIATE=1). The values must be believable:
# the version list needs a build number, the platform version a major.minor.patch.
HIGH_ENTROPY = [
    ("sec-ch-ua-arch", '"x86"'), ("sec-ch-ua-platform-version", '"15.0.0"'),
    ("sec-ch-ua-full-version-list",
     f'"Google Chrome";v="{CHROME_MAJOR}.0.7390.108", "Not?A_Brand";v="8.0.0.0", "Chromium";v="{CHROME_MAJOR}.0.7390.108"'),
]


def run(negotiate=None):
    negotiate = bool(os.environ.get("NEGOTIATE")) if negotiate is None else negotiate
    client, tally = bot("hints-spoof", 4), Tally("round4_client_hints_spoof")
    r = client.get("/", NAVIGATION)
    tally.note(f"navigation: {r.status_code}")
    if r.headers.get("Accept-CH"):
        tally.note(f"the store asked for: Accept-CH: {r.headers['Accept-CH']}")
    asked = bool(r.headers.get("Accept-CH"))
    headers = FETCH[:5] + HIGH_ENTROPY + FETCH[5:] if (negotiate and asked) else FETCH
    return fetch_catalog(client, headers, tally).result()


if __name__ == "__main__":
    print("=== Round 4: consistent hints, Chromium order, contextual Sec-Fetch ===")
    finish(run())
