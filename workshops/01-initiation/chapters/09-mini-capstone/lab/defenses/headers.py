"""
W1 Ch9 — Layer: header scoring (W1 Ch4, reused as-is).

Wraps the four W1 Ch4 modules (ua_inspector, header_inspector, client_hints,
header_order) and turns each one's (score, reasons) into a Signal. Their
points were already on the 0-100 scale: a bare library User-Agent is 40,
which is "challenge" on the shared ladder.

Not included: W1 Ch4's Accept-CH negotiation. It needs a cookie round trip
per client and adds little once the session layer exists (Round 3).

What it catches: default HTTP libraries (wave 0) and headless Chromium that
leaks HeadlessChrome in its Client Hints.
What it misses: a header set copied from a real browser and replayed in the
right order (waves 1-2), and any real browser with a consistent override
(waves 3-4). Headers are free to forge; W2 Ch5 checks the TLS and HTTP/2
layers underneath, which are not.
False positives: very few on its own (W1 Ch4 measured 0 with real Chrome
and Firefox). Stale-browser points (20) put enterprise users who are a few
versions behind in "monitor".
"""

from functools import lru_cache

import header_inspector
import policy
import ua_inspector
import user_agents
from client_hints import score_client_hints
from header_inspector import score_header_consistency
from header_order import score_header_order
from ladder import Signal
from ua_inspector import score_user_agent

LOCALHOST_NAMES = {"localhost", "127.0.0.1", "[::1]"}

# Parsing a User-Agent runs hundreds of regexes, and the W1 Ch4 modules parse
# each one twice. A drop sees a few dozen distinct UAs, so cache the parse.
# ua-parser already caches its own regex results, so here it only saves
# ~0.09 -> ~0.06 ms per request; with a parser that doesn't, it is the
# difference between a cheap layer and an expensive one.
_cached_parse = lru_cache(maxsize=10_000)(user_agents.parse)
ua_inspector.parse = header_inspector.parse = _cached_parse


def check(ctx):
    """Layer entry point (Round 1)."""
    ua = ctx.headers.get("User-Agent", "")
    secure = ctx.host.split(":")[0] in LOCALHOST_NAMES
    checks = [
        ("user_agent", score_user_agent(ctx.headers)),
        ("consistency", score_header_consistency(ctx.headers, ctx.host)),
        ("client_hints", score_client_hints(ctx.headers, secure)),
        ("order", score_header_order(ctx.header_names, ua)),
    ]
    return [Signal("headers", name, round(points * policy.HEADER_WEIGHT), "; ".join(reasons))
            for name, (points, reasons) in checks if points]
