"""Load and cache an agent's signed key directory — the capstone's offline fork.

W4 Ch2's canonical module fetches `https://<origin>/.well-known/http-message-signatures-directory`
(through the lab's mock internet) and its docstring marks `directory_url` as the one line a lab
changes. This chapter runs with no side service at all, so the fork reads the same signed JWK Set
from a local file instead: `instance/keys/<authority>.json`, written by `tools/make_keys.py` as
`{"jwks": …, "headers": …}` — the directory plus the origin-binding signature headers it would
have been served with. Everything the verifier PROVES is unchanged: the binding is still checked
(`httpsig.verify_directory`), an unbound or malformed directory is still rejected and
negative-cached, and `web_bot_auth.py` (byte-identical to Ch2's) cannot tell the difference.

What the fork deliberately gives up, and why that is fine here: the SSRF/cost half of Ch2's
lesson lives in the outbound fetch, and Ch2 teaches it; the capstone's rounds are about what a
verified identity is WORTH, not how to fetch it. Redis keys stay under `lab:botauth:` so
POST /lab/reset clears the cache.
"""

from __future__ import annotations

import json
import os
from urllib.parse import urlparse

from . import httpsig

KEYS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "instance", "keys")
DIRECTORY_TTL_S = 600
NEGATIVE_TTL_S = 300
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


def directory_path(authority: str) -> str:
    """Where this lab keeps `authority`'s directory (the fork point; Ch2 fetches it instead)."""
    return os.path.join(KEYS_DIR, f"{authority}.json")


def fetch_directory(origin: str, r) -> tuple[dict | None, str]:
    """Bounded, cached, origin-bound load of an origin's JWK Set. Returns (jwks, reason)."""
    authority, why = origin_authority(origin)
    if authority is None:
        return None, why
    cached = r.get(f"{PREFIX}dir:{authority}")
    if cached:
        return json.loads(cached), "directory from cache"
    if r.get(f"{PREFIX}dir-neg:{authority}"):
        return None, "directory load recently failed (negative cache)"

    def fail(reason):
        r.set(f"{PREFIX}dir-neg:{authority}", "1", ex=NEGATIVE_TTL_S)
        return None, reason

    path = directory_path(authority)
    if not os.path.isfile(path):
        return fail(f"no key directory for {authority} (tools/make_keys.py writes instance/keys/)")
    if os.path.getsize(path) > MAX_DIRECTORY_BYTES:
        return fail(f"directory for {authority} larger than {MAX_DIRECTORY_BYTES} bytes")
    try:
        with open(path) as fh:
            entry = json.load(fh)
        jwks, headers = entry["jwks"], {k.lower(): v for k, v in entry.get("headers", {}).items()}
    except (ValueError, KeyError, OSError):
        return fail(f"directory file for {authority} is not {{jwks, headers}} JSON")
    if not isinstance(jwks, dict) or not isinstance(jwks.get("keys"), list):
        return fail("directory is not a JWK Set")
    ok, bound = httpsig.verify_directory(jwks, headers, authority)
    if not ok:
        return fail(f"directory not bound to {authority}: {bound}")
    r.set(f"{PREFIX}dir:{authority}", json.dumps(jwks), ex=DIRECTORY_TTL_S)
    return jwks, "directory loaded and bound to origin"
