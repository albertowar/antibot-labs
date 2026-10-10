"""
Chapter 2 — Round 1 Attack: forge the JS cookie (Section 2.7)

Objective: beat the Round 1 cookie gate without running any JavaScript.
Read the challenge page once, see what the inline script computes, and
compute it in Python. Here: a regex for the array and a reverse().join().

Because the value is the same for everyone, a real attacker doesn't even
keep the regex. They hard-code the cookie after one look (FALLBACK below).

Expected results:
  - DEFENSE_LEVEL=1   → 300/300 pages
  - DEFENSE_LEVEL>=2  → 0/300, "no clearance cookie": the cookie means nothing any more

Run the demo site first:
    cd demo_site && DEFENSE_LEVEL=1 python app.py
Then run:
    python attacks/round1_cookie_forge.py
"""

import json
import re

import requests

from common import BASE_URL, CHROME_UA, report, require_local, result, scrape

FALLBACK = "ec0d7e1"   # what we read last time


def forge_cookie(html):
    """Reproduce `["7e1","c0d","e"].reverse().join("")` from the inline script."""
    m = re.search(r"var k = (\[[^\]]*\])", html)
    if not m:
        return None
    return "".join(reversed(json.loads(m.group(1))))


def run():
    require_local()
    session = requests.Session()
    session.headers["User-Agent"] = CHROME_UA
    page = session.get(f"{BASE_URL}/", timeout=10).text
    value = forge_cookie(page) or FALLBACK
    session.cookies.set("js_ok", value)
    ok, reason, seconds = scrape(session)
    return result("round1_cookie_forge", ok, reason, seconds)


if __name__ == '__main__':
    print(f"Round 1 attack: forged js_ok cookie -> {BASE_URL}")
    report(run())
