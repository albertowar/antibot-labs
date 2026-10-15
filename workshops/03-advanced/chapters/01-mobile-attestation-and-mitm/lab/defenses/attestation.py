"""
Round 2 defense (level 2): require a valid app-attestation verdict.

The store has already verified the provider's *signature* before your check runs: demo_site/ext/mobile.py
puts the decoded verdict in `ctx.attrs["attest"]`, or None when the token was missing, forged or tampered.
Your job is the policy: how many points does a buy earn from its attestation state?

A genuine request carries a verdict minted by the provider for the real app on a real device. An attacker
who has beaten certificate pinning can read and resend bytes, but cannot produce the provider's signature
for a request they made up, so `ctx.attrs["attest"]` is None for them.

    verdict = ctx.attrs["attest"]       # None, or the signed fields: appId, deviceIntegrity, nonce, ts, ...
    Signal("attestation", "<name>", points, "<detail>")

Return a block-sized signal (80; the block band starts at 75) when the buy should not be trusted as coming
from the genuine app, nothing when it should. False positives: a real customer on a build the provider
cannot attest still has a signed verdict (weak, but signed), so this layer alone hurts almost nobody. The
people it hurts are on an app version or a store the provider does not know, and that is Round 4's problem.

The check runs on the buy only (phase "action:mobile_buy"), after the request-phase app-shape check.

>>> TODO (Round 2): implement the policy below. The stub trusts everyone, so the Round 2 attack still gets
>>> through until you fill this in. Catch up any time with:  python tools/checkpoint.py --round 2 --catch-up
"""

from .mobile_core import APP_ID  # noqa: F401  (you will compare the verdict's appId with it)
from .pipeline import Check, Signal  # noqa: F401


def _check(ctx):
    verdict = ctx.attrs.get("attest")  # noqa: F841
    # TODO (Round 2): replace this stub.
    #   - verdict is None             -> no valid provider signature -> Signal("attestation", "no_verdict", 80, ...)
    #   - verdict["appId"] != APP_ID  -> signed for another app      -> Signal("attestation", "wrong_app", 80, ...)
    #   - otherwise                   -> nothing
    return None


CHECK = Check("attestation", _check, phases=("action:mobile_buy",))
