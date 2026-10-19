"""
h2_fingerprint (Round 3): the HTTP/2 connection preface must match the TLS family.

Right after the TLS handshake an HTTP/2 client sends its preface: a SETTINGS frame, usually a
WINDOW_UPDATE, sometimes PRIORITY frames, then HEADERS with the pseudo-headers in its own order.
fingerproxy encodes that in the format of Akamai's "Passive Fingerprinting of HTTP/2 Clients"
(Black Hat EU 2017):

    1:65536;2:0;4:6291456;6:262144 | 15663105 | 1:1:0:256 | m,a,s,p
    SETTINGS id:value, in order    | WINDOW_UPDATE | PRIORITY | :method :authority :scheme :path

Each browser's network stack picks these independently of its TLS library, so a client that copies
a browser's ClientHello onto a different HTTP/2 stack (impit's hyper, Go's net/http2, httpx's h2)
shows a mismatch. It compares SETTINGS, WINDOW_UPDATE and the pseudo-header order, and drops the
PRIORITY part (ja4.h2_core): fingerproxy appends every PRIORITY frame it has seen on the connection,
so a reused Chromium connection grows from `1:1:0:256` to `1:1:0:256,3:1:0:256`.

Also checked: a browser TLS family that ended up on HTTP/1.1. Every mainstream browser negotiates
h2 with an h2-capable server; scripts often force HTTP/1.1 to keep things simple.

It only judges a MEASURED fingerprint. The 40 shoppers are Python and send a claimed JA4
(`X-Lab-JA4`), which has no HTTP/2 part to compare, so for them there is nothing to judge.

What it misses: curl_cffi, wreq/rnet, tls-client and primp ship per-browser HTTP/2 profiles next to
the TLS profile (Round 3's attack).
Who it hurts: low for real browsers, but HTTP/2 SETTINGS change across browser versions too, so
this list needs the same release-day maintenance as the JA4 list. Forward proxies that downgrade to
HTTP/1.1, or re-originate HTTP/2 with their own stack, look like the impersonators this catches.
"""

from . import ja4, policy
from .pipeline import Check, Signal


def _check(ctx):
    fp = ja4.fingerprint(ctx)
    if not fp.measured:
        return None
    engine = ja4.tls_engine(fp, ja4.claimed_engine(ctx.ua.raw))
    if engine is None:
        return None
    if not fp.h2:
        return [Signal("h2_fingerprint", "http1_browser", policy.TLS_POINTS,
                       f"{engine} TLS but the client spoke HTTP/1.1")]
    if fp.h2_core not in ja4.family_h2(engine):
        return [Signal("h2_fingerprint", "h2_mismatch", policy.TLS_POINTS,
                       f"HTTP/2 SETTINGS don't match {engine}: {fp.h2_core}")]
    return None


CHECK = Check("h2_fingerprint", _check)
