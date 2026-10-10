"""
Chapter 5 — Defense Layer 3: HTTP/2 must match the TLS family (Section 5.6)

Right after the TLS handshake, an HTTP/2 client sends its connection
preface: a SETTINGS frame, usually a WINDOW_UPDATE, sometimes PRIORITY
frames, then HEADERS with the pseudo-headers in its own order. fingerproxy
encodes that in the format from Akamai's "Passive Fingerprinting of HTTP/2
Clients" (Black Hat EU 2017):

    1:65536;2:0;4:6291456;6:262144 | 15663105 | 1:1:0:256 | m,a,s,p
    SETTINGS id:value, in order    | WINDOW_UPDATE | PRIORITY | :method :authority :scheme :path

Each browser's network stack picks these independently of its TLS library,
so a client that copies a browser's ClientHello onto a different HTTP/2
stack (impit's hyper, Go's net/http2, httpx's h2) shows a mismatch.

We compare SETTINGS, WINDOW_UPDATE and the pseudo-header order, and drop the
PRIORITY part. fingerproxy appends every PRIORITY frame it has seen on the
connection, so a reused Chromium connection grows from `1:1:0:256` to
`1:1:0:256,3:1:0:256`.

Also checked: a browser TLS family that ended up on HTTP/1.1. Every
mainstream browser negotiates h2 with an h2-capable server. Scripts often
force HTTP/1.1 to keep things simple.

Why it fails:
- curl_cffi, wreq/rnet, tls-client and primp ship per-browser HTTP/2
  profiles alongside the TLS profile (Round 3).

False-positive profile:
- Low for real browsers, but HTTP/2 SETTINGS change across browser versions
  too, so this list needs the same release-day maintenance as the JA4 list.
- Forward proxies that downgrade to HTTP/1.1, or that re-originate HTTP/2
  with their own stack, look like the impersonators this catches.

Enabled when DEFENSE_LEVEL >= 3. Catches: Round 2 (impit).
"""

from edge_headers import load_known

FAMILIES = load_known()["browser_families"]


def h2_core(h2: str) -> str:
    """Drop the PRIORITY section: 'S|W|P|H' -> 'S|W|H'."""
    parts = h2.split("|")
    if len(parts) != 4:
        return h2
    settings, window_update, _priority, pseudo = parts
    return f"{settings}|{window_update}|{pseudo}"


def score_h2(fp, tls_engine):
    """tls_engine: the browser family the ClientHello matched (Layer 2), or None."""
    if tls_engine is None:
        return 0, []
    # TODO (Round 3): the TLS says "browser"; does the HTTP/2 preface agree?
    #   - fp.h2 is empty      → 50 points: browser TLS, but the client spoke HTTP/1.1
    #   - h2_core(fp.h2) not in FAMILIES[tls_engine]["h2"] → 50 points
    #   - otherwise           → 0, []
    return 0, []


if __name__ == "__main__":
    from edge_headers import EdgeFingerprint
    impit = "2:0;4:6291456;5:16384;6:262144|15597570|0|m,a,s,p"
    chrome = "1:65536;2:0;4:6291456;6:262144|15663105|1:1:0:256,3:1:0:256|m,a,s,p"
    for h2 in [chrome, impit, None]:
        print(h2, score_h2(EdgeFingerprint("t13d1516h2_8daaf6152771_x", None, h2), "chromium"))
