"""
Round 1 attack (part 2): change one cipher string.

Objective: beat the JA4 denylist without any new tooling. The attacker gives urllib3 its own
SSLContext with a shorter TLS 1.2 cipher list. That changes the cipher count in JA4_a and the
whole JA4_b hash, so the fingerprint is one the denylist has never seen. Headers stay the same
as part 1.

    before  t13d1812h1_85036bcba153_...   (on the denylist)
    after   t13d1012h1_61a7ad8aa9b6_...   (unknown, so allowed)

Exact values depend on your OpenSSL build; tools/capture_fingerprints.py shows yours.

Expected results:
  - DEFENSE_LEVEL=1 -> 200, the denylist does not know this JA4
  - DEFENSE_LEVEL>=2 -> 403, tls_family:no_browser_family (Chrome UA, no browser has this ClientHello)

Run:
    python attacks/round1_cipher_tweak.py
"""

import ssl

import requests
from requests.adapters import HTTPAdapter

from _common import CA_FILE, CHROME_HEADERS, EDGE_URL, PATH, REQUESTS, finish, lab_headers, result

CIPHERS = "ECDHE+AESGCM:ECDHE+CHACHA20"     # the whole "evasion"


class TweakedTLS(HTTPAdapter):
    """urllib3 adapter whose ClientHello offers a different cipher list."""

    def init_poolmanager(self, *args, **kwargs):
        ctx = ssl.create_default_context(cafile=CA_FILE)
        ctx.set_ciphers(CIPHERS)
        kwargs["ssl_context"] = ctx
        return super().init_poolmanager(*args, **kwargs)


def run():
    out = []
    with requests.Session() as s:
        s.mount("https://", TweakedTLS())
        for _ in range(REQUESTS):
            r = s.get(EDGE_URL + PATH, headers={**CHROME_HEADERS, **lab_headers("cipher_tweak")}, verify=CA_FILE, timeout=15)
            out.append(result(r.status_code, r.headers, r.json() if r.ok else None))
    return out


if __name__ == "__main__":
    print(f"=== Round 1b: same headers, ciphers={CIPHERS!r} ===")
    finish(run())
