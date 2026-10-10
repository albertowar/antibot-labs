"""
Chapter 5 — Round 1 Attack (part 2): change one cipher string (Section 5.8)

Objective: beat the JA4 denylist without any new tooling. The attacker gives
urllib3 its own SSLContext with a shorter TLS 1.2 cipher list. That changes
the cipher count in JA4_a and the whole JA4_b hash, so the fingerprint is
one the denylist has never seen. Headers stay the same as part 1.

    before  t13d1812h1_85036bcba153_b26ce05bbdd6   (on the denylist)
    after   t13d1012h1_61a7ad8aa9b6_…              (unknown → allowed)

Exact values depend on your OpenSSL build; tools/capture_fingerprints.py
shows yours.

Expected results:
  - DEFENSE_LEVEL=1 → 200, the denylist doesn't know this JA4
  - DEFENSE_LEVEL=2 → 403, [L2] UA claims chromium but JA4 … matches no browser family

Run:
    python attacks/round1_cipher_tweak.py
"""

import ssl

import requests
from requests.adapters import HTTPAdapter

from _lab import BASE_URL, CA_FILE, CHROME_HEADERS, report, to_result

PATH = "/api/products"
REQUESTS = 10
CIPHERS = "ECDHE+AESGCM:ECDHE+CHACHA20"     # the whole "evasion"


class TweakedTLS(HTTPAdapter):
    """urllib3 adapter whose ClientHello offers a different cipher list."""

    def init_poolmanager(self, *args, **kwargs):
        ctx = ssl.create_default_context(cafile=CA_FILE)
        ctx.set_ciphers(CIPHERS)
        kwargs["ssl_context"] = ctx
        return super().init_poolmanager(*args, **kwargs)


def run():
    results = []
    with requests.Session() as s:
        s.mount("https://", TweakedTLS())
        for _ in range(REQUESTS):
            r = s.get(BASE_URL + PATH, headers=CHROME_HEADERS, verify=CA_FILE, timeout=10)
            results.append(to_result(PATH, r.status_code, r.json()))
    return results


if __name__ == "__main__":
    print(f"=== Round 1b: same headers, ciphers={CIPHERS!r} ===")
    report(run())
