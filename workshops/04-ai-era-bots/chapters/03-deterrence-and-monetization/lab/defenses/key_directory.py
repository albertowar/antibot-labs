"""Fetch and cache an agent's signed key directory. Ships done; shared byte-for-byte across chapters.

A Web Bot Auth signature names its signer with `Signature-Agent: "https://example.com"`. The
verifier discovers the signer's public keys at

    https://example.com/.well-known/http-message-signatures-directory

a JWK Set served with a signature of its own (`("@authority";req)`, tag
`http-message-signatures-directory`) that binds the keys to the origin that serves them. This
module is the *fetch* half of verification: get the directory, prove it belongs to the origin,
cache the answer. `web_bot_auth.verify()` is the other half.

Why it is its own module: it is the part of the verifier that makes an outbound request on the
request path, which is where verifiers get hurt.

  * **SSRF.** The URL is attacker-chosen (any `Signature-Agent` value). Accept only an https
    origin with no path, query, credentials or port games; never follow redirects; cap the body
    (MAX_DIRECTORY_BYTES) and the wait (FETCH_TIMEOUT_S). The lab sends the fetch to the mock
    internet, a side service on this machine, guarded by `labnet`; production sends it to the
    origin and should also refuse private and link-local resolutions.
  * **Cost.** One fetch per origin per DIRECTORY_TTL_S, shared by every worker through Redis.
    A failed fetch is cached too (NEGATIVE_TTL_S), or an attacker who points `Signature-Agent`
    at a dead host makes every request pay the timeout.
  * **Trust.** A directory that is not bound to its origin is rejected. A valid directory proves
    "this origin published these keys", not "this origin is trustworthy": that decision is
    policy (`web_bot_auth.trust`).
  * **Revocation.** None exists. Removing a key from the directory is the only remedy, and it
    only takes effect when your cache refreshes: keep DIRECTORY_TTL_S short.

Redis keys live under `lab:botauth:` so POST /lab/reset clears them.
"""

from __future__ import annotations

import json
from urllib.parse import urlparse

import httpx
import labnet

from . import httpsig

DIRECTORY_TTL_S = 600
NEGATIVE_TTL_S = 300
FETCH_TIMEOUT_S = 2.0
MAX_DIRECTORY_BYTES = 64 * 1024
PREFIX = "lab:botauth:"


def origin_authority(origin: str) -> tuple[str | None, str]:
    """(authority, reason). The authority (host[:port], lower case) of a Signature-Agent origin, or None."""
    try:
        u = urlparse(origin)
        port = u.port
    except ValueError:
        return None, f"Signature-Agent {origin!r} is not a URL"
    if u.scheme != "https" or not u.hostname:
        return None, f"Signature-Agent {origin!r} is not an https origin"
    if u.username or u.password or u.path not in ("", "/") or u.query or u.fragment:
        return None, f"Signature-Agent {origin!r} is not a bare origin"
    return (f"{u.hostname.lower()}:{port}" if port else u.hostname.lower()), ""


def directory_url(authority: str) -> str:
    """Where the lab fetches `authority`'s directory.

    Production: f"https://{authority}{httpsig.DIRECTORY_PATH}". The lab has no internet, so the
    mock internet (MOCK_URL) multiplexes origins by path and plays every operator's website.
    This is the one line to change to point the verifier at the real world.
    """
    return f"{labnet.target('MOCK_URL', 'http://127.0.0.1:5001')}/dir/{authority}{httpsig.DIRECTORY_PATH}"


def fetch_directory(origin: str, r) -> tuple[dict | None, str]:
    """Bounded, cached, origin-bound fetch of an origin's JWK Set. Returns (jwks, reason)."""
    authority, why = origin_authority(origin)
    if authority is None:
        return None, why
    cached = r.get(f"{PREFIX}dir:{authority}")
    if cached:
        return json.loads(cached), "directory from cache"
    if r.get(f"{PREFIX}dir-neg:{authority}"):
        return None, "directory fetch recently failed (negative cache)"

    def fail(reason):
        r.set(f"{PREFIX}dir-neg:{authority}", "1", ex=NEGATIVE_TTL_S)
        return None, reason

    try:
        resp = httpx.get(directory_url(authority), timeout=FETCH_TIMEOUT_S, follow_redirects=False)
    except httpx.HTTPError as exc:
        return fail(f"directory fetch failed: {exc.__class__.__name__}")
    if resp.status_code != 200 or len(resp.content) > MAX_DIRECTORY_BYTES:
        return fail(f"directory fetch rejected: status {resp.status_code}, {len(resp.content)} bytes")
    try:
        jwks = resp.json()
    except ValueError:
        return fail("directory is not JSON")
    if not isinstance(jwks, dict) or not isinstance(jwks.get("keys"), list):
        return fail("directory is not a JWK Set")
    ok, bound = httpsig.verify_directory(jwks, {k.lower(): v for k, v in resp.headers.items()}, authority)
    if not ok:
        return fail(f"directory not bound to {authority}: {bound}")
    r.set(f"{PREFIX}dir:{authority}", json.dumps(jwks), ex=DIRECTORY_TTL_S)
    return jwks, "directory fetched and bound to origin"
