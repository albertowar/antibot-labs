"""
Round 3 defense (level 3): bind the attestation to THIS request.

Round 2 made the attacker produce a provider-signed verdict. Round 3's attacker does not forge one: they
*lift a genuine verdict* out of a real request they captured and replay it on their own request. The lifted
verdict has a perfect provider signature, so the attestation check is happy. You must catch that it does
not belong to *this* request.

Three independent checks (any one is a block-sized signal):

  1. Request binding. A genuine verdict carries requestHash = sha256 of the canonical request (method, path,
     body). Recompute it from the request in front of you and compare. A replay onto a different body or
     path will not match.
  2. Freshness. The verdict carries the time the provider minted it; reject a stale one.
  3. Replay. The verdict carries a server-issued nonce (GET /api/mobile/nonce). Each nonce is single-use:
     spend it in Redis, and reject one the server never issued, one that is missing, or one already spent.

    verdict = ctx.attrs["attest"]       # requestHash, nonce, ts (the signature was checked already)
    body    = ctx.attrs["body"]         # the exact request bytes: hash THESE, not a re-serialised JSON
    now_ms  = ctx.attrs["now_ms"]
    ctx.redis                           # keys: mobile_core.ISSUED_PREFIX + nonce, mobile_core.SPENT_PREFIX + nonce

    expected = request_hash(ctx.method, ctx.path, body)
    ctx.redis.set(SPENT_PREFIX + nonce, 1, nx=True, ex=...) is None  ->  the nonce was already spent

Costs: one Redis round trip per buy, and one more request (the nonce) per purchase for the app. The client
clock never matters: freshness compares the provider's timestamp with the server's.

>>> TODO (Round 3): implement the checks below; the stub trusts everyone.
>>> Catch up with:  python tools/checkpoint.py --round 3 --catch-up
"""

from .mobile_core import ISSUED_PREFIX, SPENT_PREFIX, request_hash  # noqa: F401
from .pipeline import Check, Signal  # noqa: F401

FRESH_MS = 120_000  # two minutes


def _check(ctx):
    verdict = ctx.attrs.get("attest")
    if verdict is None:
        return None  # the attestation check owns a missing verdict
    # TODO (Round 3): replace this stub with the three checks described above. One signal per failed check,
    # each worth 80:  "bad_binding", "stale", "no_nonce", "unknown_nonce", "replay".
    return None


CHECK = Check("request_signing", _check, phases=("action:mobile_buy",))
