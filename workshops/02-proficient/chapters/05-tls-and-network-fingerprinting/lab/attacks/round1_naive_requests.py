"""
Chapter 5 — Round 1 Attack: every Chrome header, Python's TLS (Section 5.8)

Objective: the W1 Ch4 graduate. Every header is copied from Chrome DevTools,
in Chrome's order, with matching Client Hints. Nothing at the HTTP layer
gives it away. The ClientHello still comes from OpenSSL via urllib3: 18
ciphers, no GREASE, ALPN http/1.1 only.

Expected results:
  - DEFENSE_LEVEL=0 → 200, scraped
  - DEFENSE_LEVEL=1 → 403, [L1] JA4 on library denylist: python-requests …

Run the demo site and the edge first (see README), then:
    python attacks/round1_naive_requests.py
"""

import requests

from _lab import BASE_URL, CA_FILE, CHROME_HEADERS, report, to_result

PATH = "/api/products"
REQUESTS = 10


def run():
    """Scrape REQUESTS times; return one result per request (used by tools/checkpoint.py)."""
    results = []
    with requests.Session() as s:
        for _ in range(REQUESTS):
            r = s.get(BASE_URL + PATH, headers=CHROME_HEADERS, verify=CA_FILE, timeout=10)
            results.append(to_result(PATH, r.status_code, r.json()))
    return results


if __name__ == "__main__":
    print("=== Round 1: copied Chrome headers on python-requests ===")
    report(run())
