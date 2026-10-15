"""
Round 1 defense (client side): certificate pinning in the app

MitM works because the interception proxy presents its OWN certificate and the
client accepts it. A pinned client refuses: it checks the server's public key
(SPKI) against a hash baked into the app and aborts the TLS session on a
mismatch. The reverse engineer can no longer read their own app's traffic
through mitmproxy — they must first disable the pin on the device (Frida /
objection on a rooted phone), which is Round 2.

This module is what the genuine app's networking layer does: it decides whether to trust the certificate a
server presents, before a byte of the API is sent. It is client code, so it is not wired into the store's
ladder; attacks/round1_intercept.py calls check_pin() with the certificate a proxy would present and reports
whether the pin refused it. (The lab serves plain HTTP on loopback, like every lab in the series, so the
certificate here is a stand-in for the store's production one: tools/make_cert.py writes it.)

    pin_for_cert(cert_pem_bytes) -> "sha256/<base64 SPKI hash>"
    check_pin(server_cert_pem, expected_pin) -> raises PinMismatch on mismatch

>>> TODO (Round 1): implement check_pin so a wrong certificate is rejected.
>>> The stub trusts any certificate (the pre-pinning app), so interception
>>> succeeds until you implement it. Catch up any time with:  python tools/checkpoint.py --round 1 --catch-up
"""

import base64
import hashlib

from cryptography import x509
from cryptography.hazmat.primitives import serialization


class PinMismatch(Exception):
    pass


def pin_for_cert(cert_pem_bytes):
    """The pin a developer bakes into the app: sha256 of the SubjectPublicKeyInfo."""
    cert = x509.load_pem_x509_certificate(cert_pem_bytes)
    spki = cert.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return "sha256/" + base64.b64encode(hashlib.sha256(spki).digest()).decode()


def check_pin(server_cert_pem, expected_pin):
    # TODO (Round 1): compute the pin of server_cert_pem and compare it to
    # expected_pin; raise PinMismatch if they differ. The stub below accepts
    # everything, which is the app BEFORE pinning — mitmproxy sails through.
    return True
