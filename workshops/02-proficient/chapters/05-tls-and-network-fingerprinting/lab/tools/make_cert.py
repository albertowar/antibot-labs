"""
W2 Ch5 — Setup: self-signed certificate for https://localhost

Writes certs/tls.crt and certs/tls.key (ECDSA P-256, valid 30 days, SAN
localhost + 127.0.0.1). The edge (fingerproxy) and tools/clienthello_dump.py
both use it. The lab clients load certs/tls.crt as their trusted CA where
the library supports it, and skip verification otherwise. Only ever do that
against your own localhost.

The certificate's key type doesn't change the client's ClientHello: the
client speaks first, so the JA4 you measure is the same against any server.

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

LAB = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CERT_DIR = os.path.join(LAB, "certs")


def main():
    os.makedirs(CERT_DIR, exist_ok=True)
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=30))
        .add_extension(x509.SubjectAlternativeName([
            x509.DNSName("localhost"),
            x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
        ]), critical=False)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=False,
                                     content_commitment=False, key_encipherment=False,
                                     data_encipherment=False, key_agreement=False,
                                     encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )
    with open(os.path.join(CERT_DIR, "tls.key"), "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption()))
    with open(os.path.join(CERT_DIR, "tls.crt"), "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    print(f"Wrote {os.path.relpath(CERT_DIR, LAB)}/tls.crt and tls.key (localhost, 30 days)")


if __name__ == "__main__":
    main()
