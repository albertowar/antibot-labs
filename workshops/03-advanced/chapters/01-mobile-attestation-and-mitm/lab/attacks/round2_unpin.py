"""
W3 Ch1 — Round 2 attack: beat the pin, then try to fake attestation

Certificate pinning (Round 1's defense) only raised the cost: on a rooted phone
the attacker disables the pin with Frida / objection (conceptual — it needs a
rooted device, so it is on the slides, not in this script) and can read and
replay the API again, exactly like Round 1.

So the store now requires an attestation token (DEFENSE_LEVEL=1). This script
shows the two things the attacker can try and why both fail:
    1. send the replayed request with NO attestation            -> 403
    2. FORGE a 'strong integrity' verdict with the attacker's own key -> 403
       (the provider's public key will not validate it)

The attacker cannot produce the provider's signature, so Round 2's defense holds.

Run:
    python attacks/round2_unpin.py
"""

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from _common import Cost, farm_identity, egress_pool, report, rng_for, summary, target
from mobile_client import MobileApp, forge_token, outcome_of


def run(sessions=6):
    base, rng, pool = target(), rng_for("round2"), egress_pool()
    results = []
    with Cost() as cost:
        for i in range(sessions):
            app = MobileApp(base=base, device="pixel8", serial=f"r2-{i}", egress=rng.choice(pool))
            app.register(farm_identity(rng))
            # Half try no attestation, half try a forged verdict. Both should fail at L1.
            resp = app.buy(attest=False) if i % 2 == 0 else app.buy(replay_token=forge_token("pixel8"))
            outcome, bought, reasons = outcome_of(resp)
            results.append({"outcome": outcome, "bought": bought, "reasons": reasons,
                            "sid": app.http.headers["X-Lab-Device"]})
            app.close()
    return summary("round2_unpin", results, cost)


if __name__ == '__main__':
    report(run())
