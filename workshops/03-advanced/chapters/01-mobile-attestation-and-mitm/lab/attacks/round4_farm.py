"""
W3 Ch1 — Round 4 attack: farm genuine attestations from emulators

The attacker can no longer forge (Round 2) or replay (Round 3), so they mint
FRESH, bound, single-use verdicts the only way left: by running the real app on
an emulator / device farm. Every token is individually valid. The catch is the
honest verdict of an emulator: no hardware-backed integrity.

This beats L2 (each request is perfectly signed and bound). The store answers
with device-verdict scoring (DEFENSE_LEVEL=3): weak integrity is friction, and
many weak-integrity devices from one egress in an hour is a farm — blocked.

Note the device profile is "emulator": the attacker runs the genuine SDK, but
mint() stamps the honest verdict of the device they actually have. They cannot
pass device="pixel8" for hardware they do not own.

Run:
    python attacks/round4_farm.py
"""

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from _common import Cost, farm_identity, egress_pool, report, rng_for, summary, target
from mobile_client import MobileApp, outcome_of


def run(sessions=8):
    base, rng, pool = target(), rng_for("round4"), egress_pool()
    # A farm rotates through a handful of egress IPs; each emulator is its own device.
    egresses = pool[:2]
    results = []
    with Cost() as cost:
        for i in range(sessions):
            app = MobileApp(base=base, device="emulator", serial=f"emu-{i}",
                            egress=egresses[i % len(egresses)])
            app.register(farm_identity(rng))
            outcome, bought, reasons = outcome_of(app.buy())  # honest flow, emulator verdict
            results.append({"outcome": outcome, "bought": bought, "reasons": reasons,
                            "sid": app.http.headers["X-Lab-Device"]})
            app.close()
    return summary("round4_farm", results, cost)


if __name__ == '__main__':
    report(run())
