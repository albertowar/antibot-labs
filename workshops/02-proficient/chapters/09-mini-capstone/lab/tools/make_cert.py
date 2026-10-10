"""
Chapter 9 — Self-signed certificate for the lab edge

JA4 is a TLS fingerprint, so the store must speak TLS. This writes a
self-signed certificate for localhost / 127.0.0.1 / ::1 into lab/instance/.

Browsers will warn about it. In your own browser click through the warning
(Advanced → Proceed). The lab scripts skip verification for localhost only.
Never ship a client that skips certificate verification for real hosts.

Run:
    python tools/make_cert.py
"""

import datetime
import ipaddress
import os

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

INSTANCE = os.path.join(os.path.dirname(__file__), "..", "instance")
CERT = os.path.join(INSTANCE, "cert.pem")
KEY = os.path.join(INSTANCE, "key.pem")


def main():
    os.makedirs(INSTANCE, exist_ok=True)
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
                      x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Antibot Workshop lab")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=90))
        .add_extension(x509.SubjectAlternativeName([
            x509.DNSName("localhost"),
            x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
            x509.IPAddress(ipaddress.ip_address("::1")),
        ]), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    with open(KEY, "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption()))
    with open(CERT, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    print(f"✅ Wrote {os.path.relpath(CERT)} and {os.path.relpath(KEY)} (valid 90 days)")


if __name__ == '__main__':
    main()
