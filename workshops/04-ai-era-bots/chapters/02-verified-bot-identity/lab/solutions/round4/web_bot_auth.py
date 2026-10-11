"""Web Bot Auth: verify a signed request, then decide what the signer is entitled to.

A signing agent sends three headers (draft-ietf-webbotauth-httpsig-protocol, RFC 9421):

    Signature-Agent: "https://chatgpt.com"
    Signature-Input: sig1=("@authority" "signature-agent");created=…;expires=…;keyid="…";nonce="…";tag="web-bot-auth"
    Signature:       sig1=:base64:

`verify()` answers one question: did the holder of a key published by the
Signature-Agent origin sign *this* message? It rebuilds the signature base from the
request it received, fetches the origin's JWK Set from
/.well-known/http-message-signatures-directory, picks the key whose RFC 7638
thumbprint equals `keyid`, and checks the Ed25519 signature plus `tag`, `created`
and `expires`. Three outcomes, kept distinct on purpose: **verified**, **invalid**
(headers present, check failed), **unverified** (no signature at all).

`policy()` answers the other question, which no signature can: should we *trust*
that origin, and is this particular message safe to act on?

  * **Discovery is not trust.** Anyone can publish a directory and sign correctly
    (Round 4's attacker does). Only origins in TRUSTED_AGENTS earn a lane.
  * **A signature over `@authority` alone is a bearer credential for its window.**
    It verifies against any method, path or body sent to that host until `expires`.
    Cap the window you accept (Cloudflare: "a minute is often sufficient").
  * **Replay inside the window is still replay.** Require a nonce and remember it
    for the window; `SET NX EX` makes the check atomic across workers.
  * **No revocation exists.** Removing a key from the directory is the only remedy,
    and it only takes effect when your cache refreshes: keep directory TTLs short.

Costs and false positives: a directory fetch is an outbound HTTPS request from the
request path (cache it, bound it, never follow redirects: SSRF is the risk); an
intermediary that rewrites the Host header or strips the signature headers turns a
genuine agent into an anonymous one; a window too short for a slow network rejects
honest clients. `verify` is enabled at DEFENSE_LEVEL >= 4, the strict policy at >= 5.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field
from urllib.parse import urlparse

import httpx

import httpsig

MOCK_URL = os.environ.get("MOCK_URL", "http://127.0.0.1:5001")
DIRECTORY_TTL_S = 600
NEGATIVE_TTL_S = 300
FETCH_TIMEOUT_S = 2.0
MAX_DIRECTORY_BYTES = 64 * 1024
MAX_WINDOW_S = 300            # longest created..expires we accept
CLOCK_SKEW_S = 60

# Trust policy: the origins we have *decided* to recognise, and what they get.
TRUSTED_AGENTS: dict[str, dict] = {
    "https://chatgpt.com": {"category": "signed-agent", "lane": "verified"},
}


@dataclass
class VerifyResult:
    status: str                    # verified | invalid | unverified
    agent: str | None = None       # the Signature-Agent origin
    keyid: str | None = None
    params: dict = field(default_factory=dict)
    reasons: list[str] = field(default_factory=list)


# ------------------------------------------------------------ the key directory

def directory_url(origin: str) -> str:
    """Production: f"{origin}{DIRECTORY_PATH}". The lab's mock internet multiplexes origins by path."""
    host = urlparse(origin).hostname or ""
    return f"{MOCK_URL}/dir/{host}{httpsig.DIRECTORY_PATH}"


def fetch_directory(origin: str, r) -> tuple[dict | None, str]:
    """Bounded, cached fetch of an origin's JWK Set. Returns (jwks, reason)."""
    host = urlparse(origin).hostname or ""
    if urlparse(origin).scheme != "https" or not host:
        return None, f"Signature-Agent {origin!r} is not an https origin"
    cached = r.get(f"dir:{origin}")
    if cached:
        return json.loads(cached), "directory from cache"
    if r.get(f"dir-neg:{origin}"):
        return None, "directory fetch recently failed (negative cache)"
    try:
        resp = httpx.get(directory_url(origin), timeout=FETCH_TIMEOUT_S, follow_redirects=False)
    except httpx.HTTPError as exc:
        r.set(f"dir-neg:{origin}", "1", ex=NEGATIVE_TTL_S)
        return None, f"directory fetch failed: {exc.__class__.__name__}"
    if resp.status_code != 200 or len(resp.content) > MAX_DIRECTORY_BYTES:
        r.set(f"dir-neg:{origin}", "1", ex=NEGATIVE_TTL_S)
        return None, f"directory fetch rejected: status {resp.status_code}, {len(resp.content)} bytes"
    try:
        jwks = resp.json()
    except ValueError:
        r.set(f"dir-neg:{origin}", "1", ex=NEGATIVE_TTL_S)
        return None, "directory is not JSON"
    ok, why = httpsig.verify_directory(jwks, {k.lower(): v for k, v in resp.headers.items()}, host)
    if not ok:
        r.set(f"dir-neg:{origin}", "1", ex=NEGATIVE_TTL_S)
        return None, f"directory not bound to {host}: {why}"
    r.set(f"dir:{origin}", json.dumps(jwks), ex=DIRECTORY_TTL_S)
    return jwks, "directory fetched and bound to origin"


# -------------------------------------------------------------------- verify

def verify(ctx, r, level: int) -> VerifyResult:
    """RFC 9421 verification of the web-bot-auth signature on this request."""
    h = ctx.headers
    if "signature-input" not in h or "signature" not in h:
        return VerifyResult("unverified", reasons=["no signature"])
    try:
        inputs = httpsig.parse_signature_input(h["signature-input"])
        sigs = httpsig.parse_signature(h["signature"])
    except ValueError as exc:
        return VerifyResult("invalid", reasons=[f"malformed signature headers: {exc}"])

    agents = httpsig.parse_signature_agent(h.get("signature-agent", ""))
    now = int(time.time())
    for label, si in inputs.items():
        if si.params.get("tag") != httpsig.WEB_BOT_AUTH_TAG:
            continue                                   # not ours; another signature may be
        origin = agents.get(label) or agents.get("*")
        if not origin:
            return VerifyResult("invalid", reasons=["Signature-Agent missing for label " + label])
        covered = {n for n, _ in si.components}
        if "signature-agent" not in covered or not ({"@authority", "@target-uri"} & covered):
            return VerifyResult("invalid", origin, reasons=["signature must cover signature-agent and @authority"])
        created, expires, keyid = si.params.get("created"), si.params.get("expires"), si.params.get("keyid")
        if not isinstance(created, int) or not isinstance(expires, int) or not keyid:
            return VerifyResult("invalid", origin, reasons=["created, expires and keyid are required"])
        if created > now + CLOCK_SKEW_S:
            return VerifyResult("invalid", origin, keyid, si.params, ["signature created in the future"])
        if expires < now:
            return VerifyResult("invalid", origin, keyid, si.params, ["signature expired"])

        jwks, why = fetch_directory(origin, r)
        if jwks is None:
            return VerifyResult("invalid", origin, keyid, si.params, [why])
        key = next((k for k in jwks.get("keys", []) if httpsig.thumbprint(k) == keyid), None)
        if key is None:
            return VerifyResult("invalid", origin, keyid, si.params, [f"keyid {keyid[:8]}… not in {origin}'s directory"])
        mctx = httpsig.MessageContext(ctx.method, ctx.authority, ctx.path, h, "http", ctx.query)
        if not httpsig.verify_signature(httpsig.public_from_jwk(key), si, sigs.get(label, b""), mctx):
            return VerifyResult("invalid", origin, keyid, si.params, ["signature does not verify against the request"])
        return VerifyResult("verified", origin, keyid, si.params,
                            [f"signed by {origin} key {keyid[:8]}… ({why})"])
    return VerifyResult("unverified", reasons=["no web-bot-auth signature among the labels"])


# -------------------------------------------------------------------- policy

def policy(res: VerifyResult, r, level: int) -> tuple[str, list[str], bool]:
    """Return (lane, reasons, block) for a *verified* signature.

    Round 5 (level >= 5): only origins in TRUSTED_AGENTS earn a lane; reject windows longer
    than MAX_WINDOW_S (block=True: a replayable credential); require a nonce and remember it
    with r.set(key, "1", nx=True, ex=MAX_WINDOW_S), blocking a duplicate as a replay.
    """
    # TODO (Round 5): trust policy, freshness window, nonce replay cache.
    return "verified", ["L4: any valid signature gets the crawler lane"], False
