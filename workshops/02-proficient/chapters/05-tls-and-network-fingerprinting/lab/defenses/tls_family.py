"""
Chapter 5 — Defense Layer 2: the UA's browser must match the TLS family (Section 5.4)

Flip from "block what we know is bad" to "a browser claim must look like a
browser". The User-Agent names an engine; the ClientHello reveals the TLS
stack that really sent it:

    UA says          expected TLS stack     JA4 a+b (2026-10)
    Chrome/Edge/…    BoringSSL              t13d1516h2_8daaf6152771   fresh connection
                                            t13d1517h2_8daaf6152771   resumed (+pre_shared_key)
    Firefox          NSS                    t13d1517h2_8daaf6152771   fresh and resumed
    Safari, and      Apple TLS              t13d2013h2_a09f3c656075   (unverified)
    every iOS browser

We key on JA4 parts a+b only. Part c (extensions + signature algorithms) is
more specific, but fingerproxy v1.2.3 hashes Chromium's GREASE sig-alg into
it, so a single Chrome shows up to 16 different c values (Round 0).

Note the collision: a *resumed* Chrome connection and a *fresh* Firefox 155
connection have the same a+b. So the question this layer asks is "is the
ClientHello consistent with the engine the UA claims?", not "which browser
is this?". A Chrome UA on t13d1517h2_8daaf6152771 is consistent; so is a
Firefox UA. Ambiguity like this is normal: a fingerprint narrows the set of
possible clients, it rarely names one.

Why it fails:
- Anything that reproduces the browser's cipher list, extension count and
  ALPN passes: impit, curl_cffi, wreq, uTLS (Rounds 2–3).

False-positive profile (this is where TLS checks start to hurt):
- TLS-inspecting middleboxes (corporate proxies, antivirus HTTPS scanning)
  re-originate the connection with *their* stack while the UA stays Chrome.
- iOS: Chrome/Firefox/Edge on iOS must use WebKit and Apple's TLS. Their UAs
  say CriOS/FxiOS/EdgiOS, so map them to webkit, not to their desktop engine.
- Session resumption, if you forget to list the resumed shapes: every
  returning Chrome user's second connection.
- Browser releases change the ClientHello (Chrome 131 added ML-KEM; curl_cffi's
  Firefox 147 profile sends 17 ciphers, real Firefox 155 sends 15). A stale
  allowlist blocks the newest browsers first, which are your most
  up-to-date users.

Enabled when DEFENSE_LEVEL >= 2. Catches: Round 1's cipher tweak, curl_cffi
with only a copied `ja3=` string or forced to HTTP/1.1, and Playwright
Chromium with a Safari UA.
"""

from edge_headers import load_known

FAMILIES = load_known()["browser_families"]


def claimed_engine(user_agent: str):
    """Which engine does the User-Agent claim? None for non-browser UAs."""
    ua = user_agent or ""
    if any(t in ua for t in ("CriOS/", "FxiOS/", "EdgiOS/")) or "iPhone" in ua or "iPad" in ua:
        return "webkit"
    if "Firefox/" in ua:
        return "gecko"
    if any(t in ua for t in ("Chrome/", "Chromium/", "Edg/", "HeadlessChrome/")):
        return "chromium"
    if "Safari/" in ua and "Version/" in ua:
        return "webkit"
    return None


def tls_families(fp):
    """Every browser family whose known ClientHello shapes include this JA4 a+b."""
    return [engine for engine, family in FAMILIES.items() if fp.ja4_ab in family["ja4_ab"]]


def tls_engine(fp, claimed=None):
    """The browser family of this ClientHello, preferring the claimed one on a tie. None if no family."""
    families = tls_families(fp)
    if claimed in families:
        return claimed
    return families[0] if families else None


def score_tls_family(fp, headers):
    claimed = claimed_engine(headers.get("User-Agent", ""))
    if claimed is None:
        return 0, []
    # TODO (Round 2): is the ClientHello consistent with the engine the UA claims?
    #   families = tls_families(fp)      e.g. ["chromium"], ["chromium", "gecko"] or []
    #   - families is empty          → 50 points: the UA claims a browser, the JA4 matches none
    #   - claimed not in families    → 50 points: e.g. Safari UA on a Chromium ClientHello
    #   - otherwise                  → 0, []
    return 0, []


if __name__ == "__main__":
    from edge_headers import EdgeFingerprint
    chrome_ua = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36"
    for ja4 in ["t13d1516h2_8daaf6152771_806a8c22fdea", "t13d1517h2_8daaf6152771_a87ad97598a9",
                "t13d1012h1_61a7ad8aa9b6_d41ae481755e", "t13d2013h2_a09f3c656075_7f0f34a4126d"]:
        print(ja4, score_tls_family(EdgeFingerprint(ja4, None, None), {"User-Agent": chrome_ua}))
