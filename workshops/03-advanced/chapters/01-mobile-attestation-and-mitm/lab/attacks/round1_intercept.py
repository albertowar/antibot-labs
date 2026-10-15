"""
Round 1 attack: intercept the mobile API and replay the buy.

The attacker put a proxy (mitmproxy) between the Lab Runner app and the store, read the plaintext
POST /api/mobile/buy call, and now replays it straight from a script with the app's User-Agent, X-App-Id and
TLS fingerprint. No attestation: just the shape of a real app request.

At level 1 (the app-shape layer only) this works: the mobile API trusts anything that looks like the app. That
is the problem Round 1 exposes. The DEFENSE for this round is certificate pinning in the app
(defenses/pinned_client.py), which stops the attacker reading their own traffic in the first place:
pin_refuses() hands check_pin() the certificate a MitM proxy would present and reports whether the app refused it.

For the LIVE interception demo with a real proxy, see attacks/mitm_capture.py and the README. This script is
the scripted, deterministic version.

    python attacks/round1_intercept.py
"""

from _common import Cost, DROP_SKU, MobileApp, farm_identity, finish, rng_for, summary, world_pool


def pin_refuses():
    """Does a pinned client refuse the certificate an intercepting proxy presents? False until check_pin is written."""
    from defenses import pinned_client
    import make_cert
    expected_pin = pinned_client.pin_for_cert(make_cert.ensure())     # baked into the app at build time
    proxy_cert = make_cert.make_cert_pem("localhost", "MitM proxy")   # a different key: mitmproxy's own certificate
    try:
        pinned_client.check_pin(proxy_cert, expected_pin)
        return False   # the stub accepted the proxy's certificate: interception succeeds
    except pinned_client.PinMismatch:
        return True    # the pin held: the app aborts the connection


def run(sessions=6):
    rng, pool, results = rng_for("round1"), world_pool("cloud_vm"), []
    with Cost() as cost:
        for i in range(sessions):
            app = MobileApp("bot:intercept", device="pixel8", serial=f"r1-{i}", ip=rng.choice(pool))
            app.register(farm_identity(rng))
            app.buy(DROP_SKU, attest=False)               # the faithful replay, no attestation
            results.append(app.result())
    return summary("round1_intercept", results, cost, pin_refuses=pin_refuses())


if __name__ == "__main__":
    out = run()
    print(f"pinning refuses an intercepted certificate: {out['pin_refuses']}  "
          f"(False = not implemented yet; edit defenses/pinned_client.py)")
    finish(out)
