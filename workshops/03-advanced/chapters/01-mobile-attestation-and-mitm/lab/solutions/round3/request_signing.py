"""
W3 Ch1 — L2 defense: bind the attestation to THIS request  (Round 3, reference)
"""

from mobile_core import request_hash

FRESH_MS = 120_000  # 2 minutes


def score(ctx, verdict, store):
    if verdict is None or not ctx["path"].startswith("/api/mobile/"):
        return 0, []  # L1 already handled a missing verdict
    points, reasons = 0, []

    # 1. Request binding: the verdict must be for this exact request.
    expected = request_hash(ctx["method"], ctx["path"], ctx["body"])
    if verdict.get("requestHash") != expected:
        points += 60
        reasons.append("Attestation requestHash does not match this request (lifted/replayed verdict)")

    # 2. Freshness: reject stale verdicts.
    ts = verdict.get("ts") or 0
    if abs(ctx["now_ms"] - ts) > FRESH_MS:
        points += 60
        reasons.append(f"Stale attestation: {abs(ctx['now_ms'] - ts) // 1000}s old (limit {FRESH_MS // 1000}s)")

    # 3. Replay: the server-issued nonce is single-use.
    nonce = verdict.get("nonce")
    if not nonce:
        points += 60
        reasons.append("Attestation carries no server nonce")
    else:
        issued = store.get(f"issued:{nonce}")
        if not issued:
            points += 60
            reasons.append("Attestation nonce was never issued by this server (or already expired)")
        elif not store.set(f"spent:{nonce}", 1, nx=True, ex=FRESH_MS // 1000 + 60):
            points += 60
            reasons.append("Attestation nonce already spent (replay)")
    return points, reasons
