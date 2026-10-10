"""
W3 Ch1 — Round 3 attack: lift and replay a genuine attestation token

The attacker cannot forge a verdict, so they steal one. Via the (unpinned) MitM
they capture a GENUINE, provider-signed verdict out of a real buy and replay it
on a request for their own account. The signature is perfect, so attestation
(L1) is satisfied.

This beats L1. The store answers with request signing (DEFENSE_LEVEL=2): the
verdict is bound to one request (requestHash) and to a single-use server nonce,
with a freshness window. The lifted verdict's nonce is already spent by the
real buy it came from, so the replay is rejected.

For determinism the script captures the exact token a legitimate buy used
(so its nonce is already spent), then replays it. Live, the attacker sniffs it
off the wire.

Run:
    python attacks/round3_replay.py
"""

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from _common import Cost, farm_identity, egress_pool, report, rng_for, summary, target
from mobile_client import MobileApp, outcome_of


def run(sessions=6):
    base, rng, pool = target(), rng_for("round3"), egress_pool()
    results = []
    with Cost() as cost:
        for i in range(sessions):
            egress = rng.choice(pool)
            # 1. A genuine buy happens (a different, legit account); the attacker
            #    captures the exact verdict it used. That nonce is now spent.
            victim = MobileApp(base=base, device="pixel8", serial=f"v3-{i}", egress=egress)
            victim.register(farm_identity(rng))
            token, body = victim.mint_buy("lab-runner-9")
            victim._post_buy(body, token)          # the real buy spends the nonce
            victim.close()

            # 2. The attacker replays that captured verdict for their own account.
            attacker = MobileApp(base=base, device="pixel8", serial=f"a3-{i}", egress=egress)
            attacker.register(farm_identity(rng))
            outcome, bought, reasons = outcome_of(attacker.buy(replay_token=token))
            results.append({"outcome": outcome, "bought": bought, "reasons": reasons,
                            "sid": attacker.http.headers["X-Lab-Device"]})
            attacker.close()
    return summary("round3_replay", results, cost)


if __name__ == '__main__':
    report(run())
