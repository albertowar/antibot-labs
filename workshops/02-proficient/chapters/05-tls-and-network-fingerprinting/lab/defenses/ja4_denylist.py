"""
Chapter 5 — Defense Layer 1: JA4 denylist of HTTP libraries (Section 5.3)

Block the exact JA4 of HTTP libraries you have observed: python-requests,
httpx, curl, Go net/http, Node undici and so on. A library's ClientHello is
fixed by its TLS stack, so its JA4 is stable across requests, machines with
the same OpenSSL build, and User-Agent changes. That's why this catches the
W1 Ch4 attacker who copied every header from DevTools.

Why it fails:
- One `ssl_context.set_ciphers(...)` call changes JA4_b (and the cipher count
  in JA4_a). A denylist only knows what it has already seen (Round 1 attack).
- Library JA4s depend on the OpenSSL build. macOS python.org builds,
  Homebrew, Debian and Alpine can all differ. Capture your own
  (tools/capture_fingerprints.py) rather than trusting a public list.

False-positive profile:
- Your own integrations: partners, mobile backends, monitoring and uptime
  checks all use these libraries. They need an authenticated exception path,
  not an IP allowlist.
- Cost: one dict lookup per request.

Enabled when DEFENSE_LEVEL >= 1. Catches: Round 1 (naive requests with
copied Chrome headers).
"""

from edge_headers import load_known

LIBRARY_JA4 = load_known()["library_ja4"]

# Integrations you have issued credentials to. In production: a key store,
# scoped tokens, mTLS client certs; never a string in the source.
PARTNER_KEYS = {"partner-demo-key": "Acme Partner Sync"}


def is_partner(headers) -> bool:
    auth = headers.get("Authorization", "")
    return auth.startswith("Bearer ") and auth[len("Bearer "):] in PARTNER_KEYS


def score_denylist(fp, headers):
    """Return (points, reasons) for a request's edge fingerprint."""
    # TODO (Round 1): two rules, in this order.
    #   1. Requests carrying a partner key (is_partner(headers)) are never denied:
    #      they use python-requests too, and blocking them is a false positive.
    #   2. If fp.ja4 is a key of LIBRARY_JA4, return 50 points and a reason that
    #      names the library, e.g. f"JA4 on library denylist: {label} ({fp.ja4})".
    #   Otherwise return 0, [].
    return 0, []


if __name__ == "__main__":
    from edge_headers import EdgeFingerprint
    for ja4 in ["t13d1812h1_85036bcba153_b26ce05bbdd6", "t13d1012h1_61a7ad8aa9b6_d41ae481755e"]:
        print(ja4, score_denylist(EdgeFingerprint(ja4, None, None), {}))
