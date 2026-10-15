"""
The certificate the app pins (Round 1).

A real app ships the hash of its server's public key (the SPKI pin) and refuses any TLS session whose server
key hashes differently. This lab serves plain HTTP on loopback like every lab in the series, so there is no
TLS handshake to refuse; instead this writes a self-signed certificate for localhost to instance/cert.pem
that STANDS FOR the store's production certificate, and attacks/round1_intercept.py hands check_pin() that
certificate and the one a MitM proxy would present in its place. The private key is discarded: nothing serves
this certificate.

    python tools/make_cert.py             # (re)write instance/cert.pem
"""

import datetime
import ipaddress
import os

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

INSTANCE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "instance")
CERT = os.path.join(INSTANCE, "cert.pem")


def make_cert_pem(common_name="localhost", org="Kestrel Outfitters lab"):
    """A fresh self-signed certificate (and a key nobody keeps) as PEM bytes."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name),
                      x509.NameAttribute(NameOID.ORGANIZATION_NAME, org)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=90))
        .add_extension(x509.SubjectAlternativeName([
            x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM)


def ensure():
    """The store certificate the app pins: written once to instance/cert.pem. Returns its PEM bytes."""
    if not os.path.exists(CERT):
        os.makedirs(INSTANCE, exist_ok=True)
        with open(CERT, "wb") as f:
            f.write(make_cert_pem())
    with open(CERT, "rb") as f:
        return f.read()


if __name__ == "__main__":
    ensure()
    print(f"ok  {os.path.relpath(CERT)}")
