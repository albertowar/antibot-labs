"""
W3 Ch1 — L2 defense: bind the attestation to THIS request  (Round 3)

Round 2 made the attacker produce a provider-signed verdict. Round 3's attacker
does not forge one — they *lift a genuine verdict* out of a real request they
captured, and replay it on their own request. The lifted verdict has a perfect
provider signature, so L1 is happy. You must catch that it does not belong to
*this* request.

Two independent checks (either one blocks):

  1. Request binding. A genuine verdict carries requestHash = sha256 of the
     canonical request (method, path, body). Recompute it from the request in
     front of you and compare. A replay onto a different body/path will not match.

  2. Replay + freshness. The verdict carries a server-issued nonce and a
     timestamp. Each nonce is single-use (spend it in Redis); reject a reused
     nonce, a nonce the server never issued, or a stale timestamp.

    score(ctx, verdict, store) -> (points, [reasons])

ctx has: method, path, body (bytes), now_ms. verdict has: requestHash, nonce, ts.

>>> TODO (Round 3): implement the checks below; the stub trusts everyone.
>>> Catch up with:  python tools/checkpoint.py --round 3 --catch-up
"""

from mobile_core import request_hash

FRESH_MS = 120_000  # 2 minutes


def score(ctx, verdict, store):
    # TODO (Round 3): replace this stub with the two checks described above.
    #   expected = request_hash(ctx["method"], ctx["path"], ctx["body"])
    #   nonce single-use:  store.set(f"spent:{nonce}", 1, nx=True, ex=...) is False -> replay
    return 0, []
