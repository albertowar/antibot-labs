"""
ja4_denylist (Round 1): block the exact JA4 of HTTP libraries you have observed.

python-requests, httpx, curl, Go net/http, Node undici and the rest: a library's ClientHello is
fixed by its TLS stack, so its JA4 is stable across requests, across machines with the same
OpenSSL build, and across User-Agent changes. That is why this catches W1 Ch4's attacker, who
copied every header from DevTools: nothing at the HTTP layer gives it away, but the handshake
still says "OpenSSL via urllib3".

What it misses: one `ssl_context.set_ciphers(...)` call changes JA4_b (and the cipher count in
JA4_a). A denylist only knows what it has already seen (Round 1's attack). Library JA4s also
depend on the OpenSSL build: macOS python.org builds, Homebrew, Debian and Alpine all differ, so
capture your own (tools/capture_fingerprints.py) rather than trusting a public list.

Who it hurts: your own integrations. Partners, mobile backends, monitoring and uptime checks all
use these libraries. They need an authenticated exception path, not an IP allowlist; comment out
the partner rule and the checkpoint shows `partner_api` blocked.

The first rule is not a lesson, it is plumbing: behind a TLS edge, a request with no fingerprint
skipped the edge (or came from something that cannot be fingerprinted). Cost: one dict lookup.
"""

from . import ja4, policy
from .pipeline import Check, Signal

# Integrations you have issued credentials to. In production: a key store, scoped tokens, mTLS
# client certificates; never a string in the source.
PARTNER_KEYS = {"partner-demo-key": "Acme Partner Sync"}


def is_partner(ctx):
    auth = ctx.header("Authorization", "") or ""
    return auth.startswith("Bearer ") and auth[len("Bearer "):] in PARTNER_KEYS


def _check(ctx):
    fp = ja4.fingerprint(ctx)
    if not fp.present:
        return [Signal("ja4_denylist", "no_fingerprint", policy.NO_FINGERPRINT_POINTS,
                       "no TLS fingerprint: the request did not come through the TLS edge")]
    # TODO (Round 1): two rules, in this order.
    #   1. A request with a partner key (is_partner(ctx)) is never denied: it uses python-requests too,
    #      and blocking it is a false positive.
    #   2. If this JA4 is a known HTTP library (ja4.library_label(fp) returns its name, or None),
    #      return one Signal("ja4_denylist", "library_ja4", policy.TLS_POINTS, <detail naming the library>).
    #   Otherwise return None.
    return None


CHECK = Check("ja4_denylist", _check)
