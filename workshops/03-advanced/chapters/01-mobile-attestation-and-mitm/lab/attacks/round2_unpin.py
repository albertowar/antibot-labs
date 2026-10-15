"""
Round 2 attack: beat the pin, then try to fake attestation.

Certificate pinning (Round 1's defense) only raised the cost: on a rooted phone the attacker disables the pin
with Frida / objection (conceptual: it needs a rooted device, so it is on the slides, not in this script) and can
read and replay the API again, exactly like Round 1.

So the store now requires an attestation verdict (level 2). This script shows the two things the attacker can
try, and why both fail:
    1. send the replayed request with NO attestation                     -> refused
    2. FORGE a 'strong integrity' verdict with the attacker's own key    -> refused
       (the provider's public key will not validate it, so the store sees no verdict at all)

The attacker cannot produce the provider's signature, so Round 2's defense holds.

    python attacks/round2_unpin.py
"""

from _common import Cost, DROP_SKU, MobileApp, farm_identity, finish, forge_token, rng_for, summary, world_pool


def run(sessions=6):
    rng, pool, results = rng_for("round2"), world_pool("cloud_vm"), []
    with Cost() as cost:
        for i in range(sessions):
            app = MobileApp("bot:unpin", device="pixel8", serial=f"r2-{i}", ip=rng.choice(pool))
            app.register(farm_identity(rng))
            # Half send nothing, half send a forged verdict. Both should fail at the attestation check.
            app.buy(DROP_SKU, attest=False) if i % 2 == 0 else app.buy(DROP_SKU, replay_token=forge_token("pixel8"))
            results.append(app.result())
    return summary("round2_unpin", results, cost)


if __name__ == "__main__":
    finish(run())
