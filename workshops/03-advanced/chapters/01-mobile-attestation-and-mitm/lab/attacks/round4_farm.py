"""
Round 4 attack: farm genuine attestations from emulators.

The attacker can no longer forge (Round 2) or replay (Round 3), so they mint FRESH, bound, single-use verdicts
the only way left: by running the real app on an emulator or a device farm. Every verdict is individually valid.
The catch is the honest verdict of an emulator: no hardware-backed integrity.

This beats level 3 (each request is perfectly signed and bound). The store answers with device-verdict scoring
(level 4): weak integrity alone is friction, and more than three weak-integrity devices from one address in an
hour is a farm, which is blocked.

Note the device profile is "emulator": the attacker runs the genuine SDK, but mint() stamps the honest verdict
of the device they actually have. They cannot pass device="pixel8" for hardware they do not own.

    python attacks/round4_farm.py
"""

from _common import Cost, DROP_SKU, MobileApp, farm_identity, finish, rng_for, summary, world_pool


def run(sessions=12):
    rng, results = rng_for("round4"), []
    egresses = world_pool("cloud_vm")[:2]          # a farm rotates through a handful of addresses; each emulator is its own device
    with Cost() as cost:
        for i in range(sessions):
            app = MobileApp("bot:farm", device="emulator", serial=f"emu-{i}", ip=egresses[i % len(egresses)])
            app.register(farm_identity(rng))
            app.buy(DROP_SKU)                       # the honest flow, with the emulator's honest verdict
            results.append(app.result())
    return summary("round4_farm", results, cost)


if __name__ == "__main__":
    finish(run())
