"""
Signing the agent's requests as an operator (Web Bot Auth, Round 3).

A verified agent proves who operates it by signing each request with its
operator's Ed25519 key (RFC 9421, the webbotauth profile). defenses/httpsig.py
holds the signing code; here we wire it into Playwright so that EVERY request
the page makes carries the three headers:

    Signature-Agent, Signature-Input, Signature

We use Playwright's request routing to add them. The signature covers
"@authority" (the Host) and "signature-agent", exactly what the store verifies.

install_signer(context, authority, key, agent_host): sign with a real key the
store trusts — the honest verified agent.
install_header_claim(context, agent_host): add only Signature-Agent, no valid
signature — Round 3's first forgery (claiming identity without proving it).
install_replayer(context, captured): resend one captured, valid set of headers
on every request — Round 3's replay case, caught by the nonce/freshness checks.
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "defenses"))
import httpsig  # noqa: E402


def _route(context, header_fn):
    def handler(route):
        req = route.request
        extra = header_fn()
        route.continue_(headers={**req.all_headers(), **{k.lower(): v for k, v in extra.items()}})
    context.route("**/*", handler)


def install_signer(context, authority, private_key, agent_host):
    """Honest verified agent: a fresh valid signature per request."""
    def headers():
        return httpsig.sign(private_key, authority, agent_host)
    _route(context, headers)


def install_header_claim(context, agent_host):
    """Forgery A: claim an operator with no signature at all."""
    _route(context, lambda: {"Signature-Agent": f'"{agent_host}"'})


def install_replayer(context, captured_headers):
    """Forgery B: replay one captured valid signature on every request (stale nonce)."""
    _route(context, lambda: dict(captured_headers))


def capture_once(authority, private_key, agent_host):
    """A single valid header set, as if sniffed from an earlier honest request."""
    return httpsig.sign(private_key, authority, agent_host)
