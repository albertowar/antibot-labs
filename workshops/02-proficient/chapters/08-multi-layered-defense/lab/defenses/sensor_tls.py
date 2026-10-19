"""
Layer: TLS fingerprint (stand-in for W2 Ch3)

The edge passes the JA4 of the ClientHello (`ctx.edge.ja4`: measured by a TLS edge, or claimed by
the lab client over plain HTTP). Two checks: is it a known HTTP library, and does the TLS stack
agree with the browser the User-Agent claims?

An unknown JA4 scores nothing. New browser builds, embedded webviews and enterprise TLS
middleboxes produce JA4s you have never seen, and "unknown" is not "bad". Impersonation
libraries (curl_cffi, curl-impersonate and the like) defeat the first check completely; the
second only catches operators who rotate User-Agents across browsers that their TLS stack does
not imitate.
"""

from . import sensor_headers

LAYER = "tls"
SIGNALS = {
    "ja4_non_browser": "JA4 belongs to an HTTP library",
    "ja4_ua_mismatch": "JA4 is one browser, User-Agent claims another",
}

# Illustrative JA4 values, one per client stack (W2 Ch3 captures and verifies real ones)
JA4 = {
    "chrome":          "t13d1516h2_8daaf6152771_02713d6af862",
    "firefox":         "t13d1715h2_5b57614c22b0_3d5424432f57",
    "safari":          "t13d2014h2_a09f3c656075_14788d8d241b",
    "python-requests": "t13d4907h1_0d8feac7bc37_7395dae3b2f3",
    "curl":            "t13d3112h1_e8f1e7e78f70_2a3f32ed4b4d",
}
_STACK = {v: k for k, v in JA4.items()}
BROWSERS = {"chrome", "firefox", "safari"}


def sense(ctx):
    stack = _STACK.get(ctx.edge.ja4)
    if stack is None:
        return []
    if stack not in BROWSERS:
        return ["ja4_non_browser"]
    family = sensor_headers.ua_of(ctx)["family"]
    if family in BROWSERS and family != stack:
        return ["ja4_ua_mismatch"]
    return []
