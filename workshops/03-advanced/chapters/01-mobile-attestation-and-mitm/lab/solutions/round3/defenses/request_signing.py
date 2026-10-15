"""
Round 3 defense (level 3): bind the attestation to THIS request. (Reference solution.)

Binding, freshness and a single-use nonce. The nonce is the part that needs state: the server remembers the
nonces it issued (mobile.py writes them) and spends each one exactly once with SET NX, which is atomic, so two
parallel replays cannot both win. The hash covers the request *bytes* the client sent, so the app hashes the
same bytes it puts on the wire.

False positives: a client whose verdict took longer than FRESH_MS to arrive (a phone that waited on the
provider over a bad network) fails freshness; the genuine app re-requests a nonce and retries. That is a
latency cost to the real user, not a block.
"""

from .mobile_core import ISSUED_PREFIX, SPENT_PREFIX, request_hash
from .pipeline import Check, Signal

FRESH_MS = 120_000  # two minutes


def _check(ctx):
    verdict = ctx.attrs.get("attest")
    if verdict is None:
        return None  # the attestation check owns a missing verdict
    signals = []

    # 1. Request binding: the verdict must be for this exact request.
    expected = request_hash(ctx.method, ctx.path, ctx.attrs["body"])
    if verdict.get("requestHash") != expected:
        signals.append(Signal("request_signing", "bad_binding", 80, "requestHash is not this request's (lifted verdict)"))

    # 2. Freshness: reject a stale verdict.
    age = abs(ctx.attrs["now_ms"] - (verdict.get("ts") or 0))
    if age > FRESH_MS:
        signals.append(Signal("request_signing", "stale", 80, f"{age // 1000}s old (limit {FRESH_MS // 1000}s)"))

    # 3. Replay: the server-issued nonce is single-use.
    nonce = verdict.get("nonce")
    if not nonce:
        signals.append(Signal("request_signing", "no_nonce", 80, "the verdict carries no server nonce"))
    elif not ctx.redis.get(ISSUED_PREFIX + nonce):
        signals.append(Signal("request_signing", "unknown_nonce", 80, "never issued by this server, or expired"))
    elif not ctx.redis.set(SPENT_PREFIX + nonce, 1, nx=True, ex=FRESH_MS // 1000 + 60):
        signals.append(Signal("request_signing", "replay", 80, "nonce already spent"))
    return signals or None


CHECK = Check("request_signing", _check, phases=("action:mobile_buy",))
