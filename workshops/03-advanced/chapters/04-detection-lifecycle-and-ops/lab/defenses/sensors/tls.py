"""
Layer: TLS fingerprint (stand-in for W2 Ch5)

The edge passes the JA4 of the ClientHello. Two checks: is it a known HTTP
library, and does the TLS stack agree with the browser the User-Agent claims?

An unknown JA4 scores nothing (W3 Ch4: the table is data with a date;
corpus.py adds what tools/refresh_corpus.py learned since). New browser builds, embedded webviews and
enterprise TLS middleboxes produce JA4s you have never seen, and "unknown"
is not "bad". Impersonation libraries (curl_cffi, curl-impersonate and the
like) defeat the first check completely; the second only catches operators
who rotate User-Agents across browsers that their TLS stack does not imitate.
"""

import json
import os

import corpus

LAYER = "tls"
SIGNALS = {
    "ja4_non_browser": "JA4 belongs to an HTTP library",
    "ja4_ua_mismatch": "JA4 is one browser, User-Agent claims another",
}

with open(os.path.join(os.path.dirname(__file__), "..", "..", "world.json")) as f:
    _JA4 = {v: k for k, v in json.load(f)["ja4"].items() if not k.startswith("_")}
BROWSERS = {"chrome", "firefox", "safari"}


def stack_of(ja4):
    """Which client stack this JA4 belongs to, per the table plus the refresh."""
    table = dict(_JA4)
    for name, value in corpus.updates().get("ja4", {}).items():
        table[value] = name.split("-")[0]   # "chrome-146" -> chrome
    return table.get(ja4)


def sense(ctx):
    stack = stack_of(ctx.ja4)
    if stack is None:
        return []
    if stack not in BROWSERS:
        return ["ja4_non_browser"]
    if ctx.ua["family"] in BROWSERS and ctx.ua["family"] != stack:
        return ["ja4_ua_mismatch"]
    return []
