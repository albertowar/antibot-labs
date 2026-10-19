"""
tls_family (Round 2): the User-Agent's browser must match the TLS family.

Flip from "block what we know is bad" to "a browser claim must look like a browser". The UA names
an engine; the ClientHello reveals the TLS stack that really sent it:

    UA says          expected TLS stack     JA4 a+b (2026-10)
    Chrome/Edge/...  BoringSSL              t13d1516h2_8daaf6152771   fresh connection
                                            t13d1517h2_8daaf6152771   resumed (+pre_shared_key)
    Firefox          NSS                    t13d1517h2_8daaf6152771   fresh and resumed
    Safari, and      Apple TLS              t13d2013h2_a09f3c656075   (unverified)
    every iOS browser

It keys on JA4 parts a+b only (defenses/ja4.py explains why part c is not usable with fingerproxy
v1.2.3). A *resumed* Chrome connection and a *fresh* Firefox 155 connection share an a+b, so the
question is "is the ClientHello consistent with the engine the UA claims?", never "which browser
is this?". Ambiguity like this is normal: a fingerprint narrows the set of possible clients, it
rarely names one.

What it misses: anything that reproduces the browser's cipher list, extension count and ALPN:
impit, curl_cffi, wreq, uTLS (Rounds 2 and 3).

Who it hurts (this is where TLS checks start to cost something):
  - TLS-inspecting middleboxes (corporate proxies, antivirus HTTPS scanning) re-originate the
    connection with *their* stack while the UA stays Chrome. The `corporate_proxy` client.
  - iOS: Chrome, Firefox and Edge on iOS must use WebKit and Apple's TLS. Their UAs say CriOS,
    FxiOS, EdgiOS, so claimed_engine() maps them to webkit, not to their desktop engine.
  - A stale allowlist: browser releases change the ClientHello (Chrome 131 added ML-KEM; curl_cffi's
    Firefox 147 profile sends 17 ciphers, real Firefox 155 sends 15). The newest browsers fail
    first, and they are your most up-to-date users.
"""

from . import ja4, policy
from .pipeline import Check, Signal


def _check(ctx):
    claimed = ja4.claimed_engine(ctx.ua.raw)          # "chromium" | "gecko" | "webkit" | None (not a browser UA)
    fp = ja4.fingerprint(ctx)
    if claimed is None or not fp.present:
        return None
    # TODO (Round 2): is the ClientHello consistent with the engine the UA claims?
    #   families = ja4.tls_families(fp)          e.g. ["chromium"], ["chromium", "gecko"] or []
    #   - no family at all        -> one Signal("tls_family", "no_browser_family", policy.TLS_POINTS, ...):
    #                                the UA claims a browser, the JA4 matches none
    #   - claimed not in families -> one Signal("tls_family", "engine_mismatch", policy.TLS_POINTS, ...):
    #                                e.g. a Safari UA on a Chromium ClientHello
    #   - otherwise               -> None
    return None


CHECK = Check("tls_family", _check)
