"""
Layer: TLS fingerprint (stand-in for W2 Ch5)

The edge passes the JA4 of the ClientHello (`ctx.edge.ja4`: measured by a TLS edge, or claimed by
the lab client over plain HTTP). Two checks: is it a known HTTP library, and does the TLS stack
agree with the browser the User-Agent claims?

An unknown JA4 scores nothing. New browser builds, embedded webviews and enterprise TLS
middleboxes produce JA4s you have never seen, and "unknown" is not "bad". Impersonation
libraries (curl_cffi, curl-impersonate and the like) defeat the first check completely; the
second only catches operators who rotate User-Agents across browsers that their TLS stack does
not imitate.

Chapter 4: the JA4 table is *data with a date* too (data/ops_world.json, captured in lab week 0;
corpus.py adds what tools/refresh_corpus.py learned since). A new browser release shows a JA4 the
table has never seen, and "unknown" scores nothing, which is exactly why a stale table goes quiet
instead of failing.
"""

from . import corpus, sensor_headers

LAYER = "tls"
SIGNALS = {
    "ja4_non_browser": "JA4 belongs to an HTTP library",
    "ja4_ua_mismatch": "JA4 is one browser, User-Agent claims another",
}

BROWSERS = {"chrome", "firefox", "safari"}


def table():
    """{ja4: stack}: the week-0 table plus whatever the refresh added ("chrome-146" -> chrome)."""
    out = {v: k for k, v in corpus.snapshot()["ja4"].items()}
    for name, value in corpus.updates().get("ja4", {}).items():
        out[value] = name.split("-")[0]
    return out


def sense(ctx):
    stack = table().get(ctx.edge.ja4)
    if stack is None:
        return []
    if stack not in BROWSERS:
        return ["ja4_non_browser"]
    family = sensor_headers.ua_of(ctx)["family"]
    if family in BROWSERS and family != stack:
        return ["ja4_ua_mismatch"]
    return []
