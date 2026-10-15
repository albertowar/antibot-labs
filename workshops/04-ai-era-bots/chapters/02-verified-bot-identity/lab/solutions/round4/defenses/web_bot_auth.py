"""Web Bot Auth: verify a signed request, then decide what the signer is entitled to.

Reference verifier (RFC 9421 HTTP Message Signatures, Ed25519; IETF draft-ietf-webbotauth-*).
A signing agent sends three headers:

    Signature-Agent: "https://chatgpt.com"
    Signature-Input: sig1=("@authority" "signature-agent");created=…;expires=…;keyid="…";nonce="…";tag="web-bot-auth"
    Signature:       sig1=:base64:

`verify()` answers one question: did the holder of a key published by the Signature-Agent
origin sign *this* message? It rebuilds the signature base from the request it received,
fetches the origin's JWK Set (defenses/key_directory.py), picks the key whose RFC 7638
thumbprint equals `keyid`, and checks the Ed25519 signature plus `tag`, `created` and
`expires`. Three outcomes, kept distinct on purpose:

    verified     the signature checks out against a key the origin published
    invalid      a Web Bot Auth signature is present and the check FAILED: a forgery, a
                 tampered message, an expired or future-dated signature, a key the origin
                 never published
    unverified   no usable Web Bot Auth signature, or the origin's directory could not be
                 fetched or is not bound to it. The client has not been proven to lie.

What the verifier reads from the request, and why it is more than `ctx.args`:

    ctx.method, ctx.host        @method, @authority (the Host header, lower case, with the port)
    ctx.path                    @path
    ctx.attrs["raw_query"]      @query and @target-uri need the RAW query string. `ctx.args` is
                                parsed (order, repeats and escapes lost), so the lab's
                                demo_site/ext/identity.py exposes `request.query_string` through an
                                enricher. A verifier that rebuilds the query from parsed args fails
                                on a signed `?a=1&a=2` or `%20`: the W4 Ch2 recon gap.
    ctx.header(...)             Signature-Agent, Signature-Input, Signature (lab `X-Lab-*`
                                headers never reach a check)

`trust()` answers the other question, which no signature can: should we *trust* that origin,
and is this particular message safe to act on?

  * **Discovery is not trust.** Anyone can publish a directory and sign correctly (Round 4's
    attacker does). Only origins in `policy.TRUSTED_AGENTS` earn a lane.
  * **A signature over `@authority` alone is a bearer credential for its window.** It verifies
    against any method, path or body sent to that host until `expires`. Cap the window you
    accept (Cloudflare: "a minute is often sufficient").
  * **Replay inside the window is still replay.** Require a nonce and remember it for the
    window; `SET NX EX` makes the check atomic across workers.
  * **No revocation exists.** See defenses/key_directory.py.

Costs and false positives: a directory fetch is an outbound request on the request path (cached,
bounded, negative-cached); an intermediary that rewrites the Host header or strips the signature
headers turns a genuine agent into an anonymous one (`@authority` no longer matches); a window
too short for a slow network rejects honest clients; a key rotated since your cache filled is an
`invalid` until the TTL runs out.

Shared byte-for-byte by every chapter that verifies agents (W4 Ch2 is the canonical copy). The
chapter-specific numbers live in policy.py: `TRUSTED_AGENTS`, `SIGNATURE_MAX_WINDOW_S`.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from . import httpsig, key_directory, policy

CLOCK_SKEW_S = 60               # how far in the future a `created` may be (clock drift between hosts)
NONCE_PREFIX = "lab:botauth:nonce:"


@dataclass
class VerifyResult:
    status: str                    # verified | invalid | unverified
    agent: str | None = None       # the Signature-Agent origin
    keyid: str | None = None
    params: dict = field(default_factory=dict)
    reasons: list[str] = field(default_factory=list)


@dataclass
class Trust:
    entitled: bool                 # may this signer have the verified lane?
    block: bool = False            # True: the message itself is hostile (stale window, replay): 403, not a lower lane
    reasons: list[str] = field(default_factory=list)


def message_context(ctx) -> httpsig.MessageContext:
    """The request as the signer saw it: method, authority, path, raw query, headers (lower-cased)."""
    return httpsig.MessageContext(ctx.method, ctx.host, ctx.path, {k.lower(): v for k, v in ctx.headers},
                                  ctx.attrs.get("scheme", "http"), ctx.attrs.get("raw_query", ""))


def verify(ctx) -> VerifyResult:
    """RFC 9421 verification of the web-bot-auth signature on this request.

    Round 4, in order:
      1. no Signature-Input/Signature header  -> VerifyResult("unverified")
      2. httpsig.parse_signature_input / parse_signature / parse_signature_agent
      3. pick the signature whose tag is httpsig.WEB_BOT_AUTH_TAG; it must cover
         "signature-agent" and "@authority" (or "@target-uri")
      4. created <= now + CLOCK_SKEW_S, expires >= now, keyid present
      5. key_directory.fetch_directory(origin, ctx.redis); find the JWK whose
         httpsig.thumbprint() == keyid
      6. message_context(ctx) and httpsig.verify_signature(public_key, si, signature_bytes, mctx)
    A failure after step 1 is "invalid" (the client sent a signature and it does not hold), except
    when the directory itself cannot be obtained or is not bound to the origin: that is
    "unverified".
    """
    sig_input, sig, agent_header = ctx.header("Signature-Input"), ctx.header("Signature"), ctx.header("Signature-Agent")
    if not sig_input or not sig:
        return VerifyResult("unverified", reasons=["web-bot-auth: no signature headers"])

    def invalid(msg, **kw):
        return VerifyResult("invalid", reasons=[f"web-bot-auth: {msg}"], **kw)

    try:
        inputs = httpsig.parse_signature_input(sig_input)
        signatures = httpsig.parse_signature(sig)
    except ValueError as exc:
        return invalid(f"malformed signature headers: {exc}")
    si = next((s for s in inputs.values() if s.params.get("tag") == httpsig.WEB_BOT_AUTH_TAG), None)
    if si is None:
        return VerifyResult("unverified", reasons=["web-bot-auth: no signature tagged web-bot-auth"])

    covered = {name: params for name, params in si.components}
    if "signature-agent" not in covered or not ({"@authority", "@target-uri"} & set(covered)):
        return invalid("signature must cover signature-agent and @authority")
    agents = httpsig.parse_signature_agent(agent_header or "")
    origin = agents.get(covered["signature-agent"].get("key", "*"))
    if not origin:
        return invalid("no Signature-Agent origin for the covered signature-agent")

    created, expires, keyid = si.params.get("created"), si.params.get("expires"), si.params.get("keyid")
    if not isinstance(created, int) or not isinstance(expires, int) or not keyid:
        return invalid("created, expires and keyid are required", agent=origin)
    now = time.time()
    if created > now + CLOCK_SKEW_S:
        return invalid("signature created in the future", agent=origin, keyid=keyid)
    if expires < now:
        return invalid(f"signature expired {int(now - expires)}s ago", agent=origin, keyid=keyid)
    if si.params.get("alg", "ed25519") != "ed25519":
        return invalid(f"unsupported alg {si.params['alg']!r}", agent=origin, keyid=keyid)
    if si.label not in signatures:
        return invalid("no Signature value for the covered label", agent=origin, keyid=keyid)

    jwks, why = key_directory.fetch_directory(origin, ctx.redis)
    if jwks is None:
        return VerifyResult("unverified", agent=origin, keyid=keyid, reasons=[f"web-bot-auth: {why}"])
    jwk = next((k for k in jwks.get("keys", []) if httpsig.thumbprint(k) == keyid), None)
    if jwk is None:
        return invalid(f"keyid {keyid[:8]}… is not in {origin}'s directory", agent=origin, keyid=keyid)
    try:
        ok = httpsig.verify_signature(httpsig.public_from_jwk(jwk), si, signatures[si.label], message_context(ctx))
    except (ValueError, KeyError):
        ok = False
    if not ok:
        return invalid("signature does not verify against the published key", agent=origin, keyid=keyid)
    return VerifyResult("verified", agent=origin, keyid=keyid, params=dict(si.params),
                        reasons=[f"web-bot-auth: valid Ed25519 signature by a key {origin} publishes"])


def trust(res: VerifyResult, ctx) -> Trust:
    """What is a *verified* signature worth? (Round 5; Round 4 trusts any valid signature.)

    Round 5: only origins in policy.TRUSTED_AGENTS are entitled; a window longer than
    policy.SIGNATURE_MAX_WINDOW_S (or a signature older than it) is a replayable credential:
    block=True; require a nonce and remember it with
    ctx.redis.set(key, "1", nx=True, ex=policy.SIGNATURE_MAX_WINDOW_S), blocking a duplicate as a replay.
    """
    # TODO (Round 5): trust policy, freshness window, nonce replay cache.
    return Trust(True, reasons=["trust() not implemented: any valid signature is entitled"])
