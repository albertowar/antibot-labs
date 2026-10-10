"""
W3 Ch1 — Round 1 attack: intercept the mobile API and replay the buy

The attacker put a proxy (mitmproxy) between the Lab Runner app and the store,
read the plaintext /api/mobile/buy call, and now replays it straight from
Python with the app's User-Agent and X-App-Id. No browser, no attestation —
just the shape of a real app request.

At DEFENSE_LEVEL=0 this works: the mobile API trusts anything that looks like
the app. That is the problem Round 1 exposes. The DEFENSE for this round is
certificate pinning in the app (see pin_demo() and defenses/pinned_client.py),
which stops the attacker reading their own traffic in the first place.

For the LIVE interception demo with a real proxy, see attacks/mitm_capture.py
and the README. This script is the scripted, deterministic version.

Run:
    python attacks/round1_intercept.py
"""

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from _common import Cost, farm_identity, egress_pool, report, rng_for, summary, target
from mobile_client import MobileApp, outcome_of


def run(sessions=6):
    base, rng, pool = target(), rng_for("round1"), egress_pool()
    results = []
    with Cost() as cost:
        for i in range(sessions):
            app = MobileApp(base=base, device="pixel8", serial=f"r1-{i}", egress=rng.choice(pool))
            app.register(farm_identity(rng))
            outcome, bought, reasons = outcome_of(app.buy(attest=False))  # faithful replay, no attestation
            results.append({"outcome": outcome, "bought": bought, "reasons": reasons,
                            "sid": app.http.headers["X-Lab-Device"]})
            app.close()
    return summary("round1_intercept", results, cost)


def pin_demo():
    """Round 1 defense: show that a pinned client refuses an intercepted certificate."""
    import datetime
    sys.path.insert(0, os.path.join(HERE, "..", "defenses"))
    import pinned_client
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    real_cert = open(os.path.join(HERE, "..", "instance", "cert.pem"), "rb").read()
    expected_pin = pinned_client.pin_for_cert(real_cert)

    # The certificate a MitM proxy (mitmproxy) would present instead: a different key.
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.timezone.utc)
    proxy_cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                  .public_key(key.public_key()).serial_number(x509.random_serial_number())
                  .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=1))
                  .sign(key, hashes.SHA256())).public_bytes(serialization.Encoding.PEM)
    try:
        pinned_client.check_pin(proxy_cert, expected_pin)
        return False  # stub accepted the proxy cert -> interception succeeds (pin not implemented)
    except pinned_client.PinMismatch:
        return True   # pin implemented -> interception refused


if __name__ == '__main__':
    report(run())
    print(f"\npinning blocks interception: {pin_demo()}  "
          f"(False = pin not implemented yet; implement defenses/pinned_client.py)")
