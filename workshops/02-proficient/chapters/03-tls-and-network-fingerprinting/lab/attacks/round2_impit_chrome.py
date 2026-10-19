"""
Round 2 attack: a browser-shaped ClientHello.

Objective: beat the UA-to-TLS-family check. impit (Apify, Apache-2.0) is a Rust HTTP client on a
patched rustls that imitates Chrome's ClientHello: same 15 ciphers, 16 extensions, ALPN h2. JA4
parts a+b match Chrome exactly, which is all tls_family looks at.

What it does not copy is Chrome's HTTP/2 stack. impit speaks HTTP/2 through hyper, whose
connection preface differs from Chromium's:

    Chromium  1:65536;2:0;4:6291456;6:262144 | 15663105 | 1:1:0:256 | m,a,s,p
    impit     2:0;4:6291456;5:16384;6:262144 | 15597570 | 0         | m,a,s,p

Expected results:
  - DEFENSE_LEVEL=2 -> 200, JA4 a+b = t13d1516h2_8daaf6152771 (the Chromium family)
  - DEFENSE_LEVEL>=3 -> 403, h2_fingerprint:h2_mismatch

Run:
    python attacks/round2_impit_chrome.py
"""

import impit

from _common import CHROME_HEADERS, EDGE_URL, PATH, REQUESTS, finish, lab_headers, result


def run():
    # impit takes a bool for verify. Disabling it is acceptable ONLY because the target is our own
    # localhost edge with a self-signed certificate (labnet refused anything else).
    headers = {k: v for k, v in CHROME_HEADERS.items() if not k.lower().startswith("sec-ch-ua")}
    headers.update(lab_headers("impit_chrome"))
    out = []
    with impit.Client(browser="chrome", verify=False, http3=False) as client:
        for _ in range(REQUESTS):
            r = client.get(EDGE_URL + PATH, headers=headers)
            out.append(result(r.status_code, r.headers, r.json() if r.status_code == 200 else None))
    return out


if __name__ == "__main__":
    print("=== Round 2: impit, browser='chrome' ===")
    finish(run())
