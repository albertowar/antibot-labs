"""
W3 Ch1 — L1 defense: require a valid app-attestation token  (Round 2)

The store already verified the provider's *signature* before calling you
(demo_site/app.py passes you the decoded verdict, or None if the token was
missing, forged or tampered). Your job is the policy: decide how many risk
points a request earns from its attestation state.

A genuine request carries a verdict minted by the provider for the real app on
a real device. A replayed-request attacker who has beaten certificate pinning
can read and resend bytes, but cannot produce the provider's signature for a
request they made up, so verify() hands you None.

    score(ctx, verdict) -> (points, [reasons])

Return 60 points (a block on the 0-100 scale) when the request should not be
trusted as coming from the genuine app, 0 when it should.

>>> TODO (Round 2): implement the policy below. The stub trusts everyone, so
>>> the Round 2 attack still gets through until you fill this in. Catch up any
>>> time with:  python tools/checkpoint.py --round 2 --catch-up
"""

from mobile_core import APP_ID


def score(ctx, verdict):
    # TODO (Round 2): replace this stub.
    #   - verdict is None  -> no valid provider signature  -> +60
    #   - verdict["appId"] != APP_ID -> signed for another app -> +60
    #   - otherwise -> 0
    return 0, []
