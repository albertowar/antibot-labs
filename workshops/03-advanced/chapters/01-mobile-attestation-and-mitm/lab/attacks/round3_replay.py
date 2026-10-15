"""
Round 3 attack: lift and replay a genuine attestation verdict.

The attacker cannot forge a verdict, so they steal one. Through the (unpinned) MitM they capture a GENUINE,
provider-signed verdict out of a real buy and replay it on a request for their own account. The signature is
perfect, so the attestation check (level 2) is satisfied.

That beats level 2. The store answers with request signing (level 3): the verdict is bound to one request
(requestHash) and to a single-use server nonce, with a freshness window. The lifted verdict's nonce was spent
by the real buy it came from, and its hash is another account's request, so the replay is refused.

For determinism the script captures the exact verdict a legitimate buy used (so its nonce is already spent),
then replays it. Live, the attacker sniffs it off the wire.

    python attacks/round3_replay.py
"""

from _common import Cost, DROP_SKU, MobileApp, farm_identity, finish, rng_for, summary, world_pool


def run(sessions=6):
    rng, pool, results = rng_for("round3"), world_pool("cloud_vm"), []
    with Cost() as cost:
        for i in range(sessions):
            ip = rng.choice(pool)
            # 1. A genuine buy happens (a different account); the attacker captures the exact verdict it used.
            #    That nonce is now spent.
            captured = MobileApp("bot:replay_capture", device="pixel8", serial=f"v3-{i}", ip=ip)
            captured.register(farm_identity(rng))
            token, body = captured.mint_buy(DROP_SKU)
            captured.post_buy(body, token)

            # 2. The attacker replays that captured verdict for their own account.
            attacker = MobileApp("bot:replay", device="pixel8", serial=f"a3-{i}", ip=ip)
            attacker.register(farm_identity(rng))
            attacker.buy(DROP_SKU, replay_token=token)
            results.append(attacker.result())
    return summary("round3_replay", results, cost)


if __name__ == "__main__":
    finish(run())
