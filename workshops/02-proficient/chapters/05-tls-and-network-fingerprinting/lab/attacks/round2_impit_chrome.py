"""
Chapter 5 — Round 2 Attack: a browser-shaped ClientHello (Section 5.8)

Objective: beat the UA ↔ TLS family check. impit (Apify, Apache-2.0) is a
Rust HTTP client on a patched rustls that imitates Chrome's ClientHello:
same 15 ciphers, 16 extensions, ALPN h2. JA4 parts a+b match Chrome
exactly, which is all Layer 2 looks at.

What it doesn't copy is Chrome's HTTP/2 stack. impit speaks HTTP/2 through
hyper, whose connection preface differs from Chromium's:

    Chromium  1:65536;2:0;4:6291456;6:262144 | 15663105 | 1:1:0:256 | m,a,s,p
    impit     2:0;4:6291456;5:16384;6:262144 | 15597570 | 0         | m,a,s,p

Expected results:
  - DEFENSE_LEVEL=2 → 200, JA4 a+b = t13d1516h2_8daaf6152771 (Chromium family)
  - DEFENSE_LEVEL=3 → 403, [L3] HTTP/2 SETTINGS don't match chromium

Run:
    python attacks/round2_impit_chrome.py
"""

import impit

from _lab import BASE_URL, CHROME_HEADERS, report, to_result

PATH = "/api/products"
REQUESTS = 10


def run():
    # impit takes a bool for verify. Disabling it is acceptable ONLY because the
    # target is our own localhost edge with a self-signed certificate.
    headers = {k: v for k, v in CHROME_HEADERS.items() if not k.lower().startswith("sec-ch-ua")}
    results = []
    with impit.Client(browser="chrome", verify=False, http3=False) as client:
        for _ in range(REQUESTS):
            r = client.get(BASE_URL + PATH, headers=headers)
            results.append(to_result(PATH, r.status_code, r.json()))
    return results


if __name__ == "__main__":
    print("=== Round 2: impit, browser='chrome' ===")
    report(run())
