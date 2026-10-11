"""
W3 Ch1 — Round 1 defense (client side): certificate pinning  (reference)
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
