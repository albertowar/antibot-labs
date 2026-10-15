"""
Signing the agent's requests as an operator (Web Bot Auth, Round 3).

A verified agent proves who operates it by signing each request with its operator's Ed25519 key
(RFC 9421, the web-bot-auth profile). attacks/_common.py holds the signer (W4 Ch2's httpsig); here we
wire it into Playwright so that EVERY request the page makes carries the three headers:

    Signature-Agent, Signature-Input, Signature

The headers are added by a context route that FALLS BACK to the one labclient.browser_context
installed, so the guard that refuses non-local requests still runs.

install_signer(context, signer): sign with a real key the store trusts: the honest verified agent
(or, with the attacker's own operator, the third forgery: valid, but not trusted).
install_header_claim(context, agent_origin): add only Signature-Agent, no signature: the first forgery.
install_replayer(context, captured): resend one captured set of headers on every request: the second.
capture_leak(signer): such a set, as a CDN log would have leaked it: signed an hour ago with a 24 h window.
"""

import time
from urllib.parse import urlparse


def _route(context, header_fn):
    def handler(route):
        req = route.request
        extra = header_fn(req)
        route.fallback(headers={**req.all_headers(), **{k.lower(): v for k, v in extra.items()}})
    context.route("**/*", handler)


def install_signer(context, signer):
    """A fresh valid signature per request."""
    def headers(req):
        u = urlparse(req.url)
        return signer.headers(u.path, u.query, req.method, authority_=u.netloc)
    _route(context, headers)


def install_header_claim(context, agent_origin):
    """Forgery A: claim an operator with no signature at all."""
    _route(context, lambda req: {"Signature-Agent": f'"{agent_origin}"'})


def install_replayer(context, captured_headers):
    """Forgery B: replay one captured set of headers on every request."""
    _route(context, lambda req: dict(captured_headers))


def capture_leak(signer, authority_):
    """A header set from an earlier honest request that ended up in a log: old, with a long window."""
    return signer.headers("/", "", "GET", authority_=authority_, created=int(time.time()) - 3600, window=24 * 3600)
