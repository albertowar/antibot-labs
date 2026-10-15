"""
Round 1 defense (client side): certificate pinning. (Reference solution.)

The pin is the hash of the certificate's public key (SPKI), not of the certificate, so a renewed certificate
on the same key still matches. Who it hurts: nobody who is honest, until the server rotates its KEY without a
backup pin shipped in the app (every installed copy then refuses the real server). Ship a second pin.
"""

import base64
import hashlib

from cryptography import x509
from cryptography.hazmat.primitives import serialization


class PinMismatch(Exception):
    pass


def pin_for_cert(cert_pem_bytes):
    cert = x509.load_pem_x509_certificate(cert_pem_bytes)
    spki = cert.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return "sha256/" + base64.b64encode(hashlib.sha256(spki).digest()).decode()


def check_pin(server_cert_pem, expected_pin):
    actual = pin_for_cert(server_cert_pem)
    if actual != expected_pin:
        raise PinMismatch(
            f"Certificate pin mismatch — refusing the connection.\n"
            f"  expected {expected_pin}\n  got      {actual}\n"
            f"This is what a pinned app does when a proxy intercepts it.")
    return True
