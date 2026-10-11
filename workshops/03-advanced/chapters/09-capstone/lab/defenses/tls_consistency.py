"""
Chapter 9 — L0 TLS consistency: does the TLS stack match the claimed browser? (W2 Ch5)

The edge parses the ClientHello and computes JA4 (demo_site/ja4.py). Here
we decide which TLS *stack* sent it and compare that with the browser the
User-Agent claims:

    UA says Chrome/Edge/Brave/Opera, stack is not Chromium (BoringSSL)   +60
    UA says Firefox, stack is not NSS                                     +60
    UA says Safari, stack is not Apple's                                  +60
    Browser UA, but the client offered no ALPN at all                     +30

How the stack is recognized: by extensions that only one stack sends, not
by a hash.

    chromium  ALPS / application_settings (0x4469 old codepoint, 0x44cd new)
    nss       record_size_limit (0x001c) and no ALPS: Firefox, Tor Browser, Camoufox
    apple     neither of those, and Safari's long cipher list (JA4 "b" a09f3c656075)
    other     everything else: OpenSSL (Python, curl), Go, Java, rustls, ...

Why not match the JA4 hash itself? Every browser release can change it. In
October 2026, curl_cffi's chrome146 and chrome150 profiles and Chromium 153
produced three different JA4 "c" hashes. Even the cipher hash ("b") is
shared: Firefox 156 (Camoufox) offers exactly Chrome's 15 ciphers. Use JA4
strings for logging, allowlists and threat-intel matching, and the parsed
ClientHello for logic like this.

What this catches: requests/httpx/Go with a browser UA, which is still the
bulk of scraping traffic.
What it does not catch: anything that really *is* the browser's TLS stack:
Playwright, Patchright, nodriver, Camoufox, and curl_cffi / curl-impersonate,
which replay a browser's ClientHello byte for byte. From Round 1 on, TLS
agrees with the UA for every attacker. That's the point of the capstone.

`python tools/doctor.py --tls` prints what each local client sends.
"""

import re

ALPS = {0x4469, 0x44CD}
RECORD_SIZE_LIMIT = 0x001C
APPLE_CIPHER_HASH = "a09f3c656075"
UA_FAMILY_TO_STACK = {"chrome": "chromium", "firefox": "nss", "safari": "apple"}


def tls_family(ctx):
    extensions = set(ctx.get("tls_extensions") or [])
    ja4 = ctx.get("ja4") or ""
    if not ja4:
        return "none"
    if extensions & ALPS:
        return "chromium"
    if RECORD_SIZE_LIMIT in extensions:
        return "nss"
    parts = ja4.split("_")
    if len(parts) == 3 and parts[1] == APPLE_CIPHER_HASH:
        return "apple"
    return "other"


def ua_family(ua):
    if re.search(r"Firefox/\d", ua):
        return "firefox"
    if re.search(r"(Chrome|Chromium|CriOS|Edg)/\d", ua):
        return "chrome"
    if re.search(r"Version/[\d.]+ (Mobile/\w+ )?Safari/", ua):
        return "safari"
    return "other"


def score_tls(ctx):
    claimed = ua_family(ctx["ua"])
    if claimed == "other":
        return 0, []  # non-browser UAs are L0 header red flags already
    points, reasons = 0, []
    stack = tls_family(ctx)
    expected = UA_FAMILY_TO_STACK[claimed]
    if stack != expected:
        points += 60
        reasons.append(f"UA claims {claimed} but the TLS stack is {stack} (JA4 {ctx['ja4']})")
    if not ctx.get("alpn"):
        points += 30
        reasons.append("Browser UA but the TLS ClientHello offered no ALPN")
    return points, reasons


if __name__ == '__main__':
    chrome_ua = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
                 "Chrome/153.0.0.0 Safari/537.36")
    python_hello = {"ua": chrome_ua, "ja4": "t13d1712h1_ab0a1bf427ad_882d495ac381",
                    "tls_extensions": [0x0000, 0x000B, 0x000A, 0x0023, 0x0016, 0x0017, 0x000D, 0x002B,
                                       0x002D, 0x0033, 0x0010, 0x0031],
                    "alpn": ["http/1.1"]}
    print("requests with a Chrome UA:", score_tls(python_hello))
