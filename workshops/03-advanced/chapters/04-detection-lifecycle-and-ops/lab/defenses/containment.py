"""
Containment with a timer: step up a whole exit ASN

When an attack is live and you do not yet understand it, you buy time by trading false positives
for false negatives. The blunt lever for a signal-less farm that hides in one ISP's address space
is to ask *everyone* who signs in from that ASN for an emailed code. It stops the farm (it does not
own the victims' mailboxes) and it challenges that ISP's real customers too. That cost is the point.

The operator turns it on with `python tools/contain.py --step-up-asn <ASN> --for-weeks 1`, which
writes data/ops_config.json with a deadline on the lab clock; defenses/config.py drops it by itself
when the clock passes it, so the 02:00 mitigation does not quietly become next quarter's policy.
Until then this check says nothing.
"""

from . import ops, sensors
from .pipeline import Check, Signal, Verdict

LAYER = "containment"
SIGNALS = {"asn_stepup": "the operator is stepping up every sign-in from this ASN"}


def _check(ctx):
    asn = ops.state(ctx)["cfg"].get("stepup_asn")
    if not asn or ctx.edge.asn != asn:
        return None
    sig = sensors.emit(ctx, LAYER, ["asn_stepup"])[0]
    return Verdict(action="allow", signals=(Signal(LAYER, sig.name, sig.points, f"AS{asn}"),), challenge="step_up")


CHECK = Check("containment", _check, phases=sensors.LOGIN)
