"""
W3 Ch1 — Round 1 defense (client side): certificate pinning in the app

MitM works because the interception proxy presents its OWN certificate and the
client accepts it. A pinned client refuses: it checks the server's public key
(SPKI) against a hash baked into the app and aborts the TLS session on a
mismatch. The reverse engineer can no longer read their own app's traffic
through mitmproxy — they must first disable the pin on the device (Frida /
objection on a rooted phone), which is Round 2.

This module is what the genuine app's networking layer does. attacks/
mobile_client.py calls check_pin() before it trusts a connection; with the pin
on and traffic routed through a proxy, the connection is refused.

    pin_for_cert(cert_pem_bytes) -> "sha256/<base64 SPKI hash>"
    check_pin(server_cert_pem, expected_pin) -> raises PinMismatch on mismatch

>>> TODO (Round 1): implement check_pin so a wrong certificate is rejected.
>>> The stub trusts any certificate (the pre-pinning app), so interception
>>> succeeds until you implement it. Reference: solutions/round1/defenses/pinned_client.py
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
