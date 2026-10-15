"""
Round 2 defense (level 2): require a valid app-attestation verdict. (Reference solution.)

The provider's signature was verified before this check runs (ctx.attrs["attest"] is the decoded verdict, or
None). The policy is two lines: no verdict, or a verdict signed for another app, is a block-sized signal.

Who it hurts: almost nobody on its own. A weak device (rooted, GrapheneOS, uncertified) still gets a *signed*
verdict, so it passes this layer; separating those from the farm is Round 4. A client that cannot reach the
provider at all (no Play services, an old iOS) has no verdict and is stopped here: budget a fallback.
"""

from .mobile_core import APP_ID
from .pipeline import Check, Signal


def _check(ctx):
    verdict = ctx.attrs.get("attest")
    if verdict is None:
        return [Signal("attestation", "no_verdict", 80, "missing, forged or not signed by the provider")]
    if verdict.get("appId") != APP_ID:
        return [Signal("attestation", "wrong_app", 80, f"signed for {verdict.get('appId')!r}")]
    return None


CHECK = Check("attestation", _check, phases=("action:mobile_buy",))
