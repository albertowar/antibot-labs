"""
Round 1 attack (part 1): every Chrome header, Python's TLS.

Objective: the W1 Ch4 graduate. Every header is copied from Chrome DevTools, in Chrome's order,
with matching Client Hints. Nothing at the HTTP layer gives it away. The ClientHello still comes
from OpenSSL via urllib3: 18 ciphers, no GREASE, ALPN http/1.1 only.

Expected results:
  - DEFENSE_LEVEL=0 -> 200, scraped
  - DEFENSE_LEVEL>=1 -> 403, ja4_denylist:library_ja4

Run the store and the edge first (README), then:
    python attacks/round1_naive_requests.py
"""

import requests

from _common import CA_FILE, CHROME_HEADERS, EDGE_URL, PATH, REQUESTS, finish, lab_headers, result


def run():
    out = []
    with requests.Session() as s:
        for _ in range(REQUESTS):
            r = s.get(EDGE_URL + PATH, headers={**CHROME_HEADERS, **lab_headers("naive_requests")}, verify=CA_FILE, timeout=15)
            out.append(result(r.status_code, r.headers, r.json() if r.ok else None))
    return out


if __name__ == "__main__":
    print("=== Round 1: copied Chrome headers on python-requests ===")
    finish(run())
