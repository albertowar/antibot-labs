"""
W3 Ch1 — L1 defense: require a valid app-attestation token  (Round 2, reference)
"""

from mobile_core import APP_ID


def score(ctx, verdict):
    if not ctx["path"].startswith("/api/mobile/"):
        return 0, []
    if verdict is None:
        return 60, ["No valid attestation: missing or unsigned by the provider"]
    if verdict.get("appId") != APP_ID:
        return 60, [f"Attestation signed for a different app: {verdict.get('appId')!r}"]
    return 0, []
