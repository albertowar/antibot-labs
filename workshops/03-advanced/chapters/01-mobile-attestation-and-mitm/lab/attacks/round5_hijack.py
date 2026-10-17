"""
Round 5 attack: steal the bearer token and use it from another device.

Rounds 2-4 hardened the BUY: a genuine verdict, bound to one request, from a device that earns trust. None of
that protects the SESSION. The mobile login hands the app a bearer token, and a bearer token is whatever string
you hold. The attacker still has the unpinned MitM from Round 1, so they lift a victim's token off the wire (in
real life also from a rooted phone, a backup, a malicious SDK or an infostealer), then act as the victim from
their OWN genuine device: a real pixel8 with a unique serial, so Round 2's attestation passes, Round 3's nonce
and binding pass, and Round 4's velocity sees one buy per device.

Each attempt reads the victim's orders, then buys. Three variants, two sessions each:

  a. bearer only          send the lifted token and no device proof (it just works against level 4)
  b. proof from own key   sign a proof with the attacker's own key (the one they CAN sign with)
  c. lifted victim proof  replay a proof captured off the wire (a genuine one, signed by the victim's key)

This beats level 4. The store answers with a device-bound session (level 5): login binds the token to the
install's public key, and every sensitive call must carry a fresh proof signed by that key. The attacker has the
token and the victim's captured proofs, but not the private key, so (a) has no proof, (b) names the wrong key
and (c) replays a single-use nonce for another request line.

    python attacks/round5_hijack.py
"""

from _common import Cost, DROP_SKU, MobileApp, farm_identity, finish, rng_for, summary, world_pool

VARIANTS = ("bearer_only", "own_key_proof", "lifted_proof")


def run(sessions=6):
    rng, pool, results = rng_for("round5"), world_pool("cloud_vm"), []
    with Cost() as cost:
        for i in range(sessions):
            variant = VARIANTS[i % len(VARIANTS)]
            # 1. A genuine victim on a hardware-backed phone signs up and reads their own orders. The MitM
            #    captures the bearer token and the exact proof header the read carried.
            victim = MobileApp("bot:hijack_victim", device="pixel8", serial=f"v5-{i}", ip=rng.choice(pool))
            victim.register(farm_identity(rng))
            victim.orders()
            stolen_bearer, stolen_proof = victim.bearer, victim.last_proof

            # 2. The attacker acts as the victim from their own device (unique serial: no device velocity).
            attacker = MobileApp("bot:hijack", device="pixel8", serial=f"a5-{i}", ip=rng.choice(pool))
            attacker.bearer = stolen_bearer
            if variant == "bearer_only":
                attacker.proof = False
            elif variant == "lifted_proof":
                attacker.proof = stolen_proof          # (the default, "own_key_proof", signs with the attacker's key)
            attacker.orders()                          # read the victim's data first
            attacker.buy(DROP_SKU)                     # then spend it: the result counted is the buy
            results.append(attacker.result())
    return summary("round5_hijack", results, cost, variants=list(VARIANTS))


if __name__ == "__main__":
    finish(run())
