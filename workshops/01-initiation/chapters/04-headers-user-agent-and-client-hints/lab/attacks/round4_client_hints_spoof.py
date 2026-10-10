"""
Chapter 4 — Round 4 Attack: Consistent Client Hints, Chrome Order, Real Context (Section 4.7)

Objective: the attacker now models a real Chrome session instead of
replaying one capture:
  - low-entropy Client Hints that agree with the UA (GREASE brand included)
  - headers emitted in Chromium's order (session defaults cleared)
  - contextual Fetch Metadata: a navigation to / first, then the same-origin
    fetch() the page makes to /api/products
  - a cookie jar, like a browser

What the attacker cannot do with a static header template: react to the
server's Accept-CH request for high-entropy hints.

Expected results:
  - DEFENSE_LEVEL=3 → 200 for every request
  - DEFENSE_LEVEL=4 → first navigation 200 (server answers with Accept-CH),
                      then 403: "[L4] Accept-CH was offered but the client ignored it"

Run the demo site first:
    cd demo_site && DEFENSE_LEVEL=3 python app.py
Then run:
    python attacks/round4_client_hints_spoof.py
"""

import os

import requests

BASE_URL = os.environ.get("DEMO_URL", "http://localhost:5000")
CHROME_MAJOR = "153"

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      f"(KHTML, like Gecko) Chrome/{CHROME_MAJOR}.0.0.0 Safari/537.36")
SEC_CH_UA = (f'"Google Chrome";v="{CHROME_MAJOR}", "Not?A_Brand";v="8", '
             f'"Chromium";v="{CHROME_MAJOR}"')

# Chromium order for a top-level navigation (Host is added first by http.client)
NAVIGATION_HEADERS = {
    "Connection": "keep-alive",
    "sec-ch-ua": SEC_CH_UA,
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": '"Windows"',
    "Upgrade-Insecure-Requests": "1",
    "User-Agent": UA,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,"
              "image/avif,image/webp,image/apng,*/*;q=0.8",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-User": "?1",
    "Sec-Fetch-Dest": "document",
    "Accept-Encoding": "gzip, deflate",
    "Accept-Language": "en-US,en;q=0.9",
}

# Chromium order for a same-origin fetch() issued by the page
FETCH_HEADERS = {
    "Connection": "keep-alive",
    "sec-ch-ua-platform": '"Windows"',
    "User-Agent": UA,
    "sec-ch-ua": SEC_CH_UA,
    "sec-ch-ua-mobile": "?0",
    "Accept": "*/*",
    "Sec-Fetch-Site": "same-origin",
    "Sec-Fetch-Mode": "cors",
    "Sec-Fetch-Dest": "empty",
    "Referer": f"{BASE_URL}/",
    "Accept-Encoding": "gzip, deflate",
    "Accept-Language": "en-US,en;q=0.9",
}


def run():
    """
    Run the attack: one navigation, then three scraping fetches.
    Returns one result per request (used by tools/checkpoint.py).
    """
    session = requests.Session()
    session.headers.clear()   # drop requests' defaults so OUR order is used

    results = []
    r = session.get(f"{BASE_URL}/", headers=NAVIGATION_HEADERS, timeout=5)
    results.append(_result("/", "navigation", r))
    for i in range(3):
        r = session.get(f"{BASE_URL}/api/products", headers=FETCH_HEADERS, timeout=5)
        results.append(_result("/api/products", f"fetch #{i + 1}", r))
    return results


def _result(path, label, r):
    reasons = r.json().get("reasons", []) if r.status_code == 403 else []
    return {"path": path, "label": label, "status": r.status_code,
            "accept_ch": r.headers.get("Accept-CH"), "reasons": reasons}


if __name__ == '__main__':
    print("=== Round 4: consistent hints, Chromium order, contextual Sec-Fetch ===")
    for result in run():
        print(f"  GET {result['path']:<13} ({result['label']}): {result['status']}")
        if result["accept_ch"]:
            print(f"    Server asked for: Accept-CH: {result['accept_ch']}")
        for reason in result["reasons"]:
            print(f"      - {reason}")
    print()
