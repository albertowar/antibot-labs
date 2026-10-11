"""Generate the two lab crawler operators' Ed25519 signing keys (run by tools/seed.py).

Round 2 (enforcement by identity) and Round 4 (pay-per-crawl) need crawlers that
sign their requests the way a registered operator would (Web Bot Auth, RFC 9421).
A real operator generates its key pair once, keeps the private half, and
publishes the public half; the site's registry (defenses/crawler_registry.py)
holds only the public key. This script plays the operator for both lab bots:

    trainbot    LabTrainBot    keyid trainbot-2026-10    (the one we govern)
    searchbot   LabSearchBot   keyid searchbot-2026-10   (the one we must not hurt)

Writes, under attacks/keys/ (gitignored):
    <name>_ed25519.pem   the private key the attack scripts sign with
    registry.json        the public keys, as the registry would publish them

Nothing here is committed. A private key in git, even a synthetic one, trips
every secret scanner and teaches the wrong habit; generating at seed time costs
nothing and models what an operator actually does. Idempotent: existing keys
are kept unless --force, so a running store keeps verifying the keys it loaded.

Run (from lab/):
    python tools/make_keys.py            # usually via: python tools/seed.py
    python tools/make_keys.py --force    # rotate; restart the store afterwards
"""

from __future__ import annotations

import argparse
import base64
import json
import os

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

HERE = os.path.dirname(os.path.abspath(__file__))
LAB_DIR = os.path.dirname(HERE)
KEYS_DIR = os.path.join(LAB_DIR, "attacks", "keys")
REGISTRY_JSON = os.path.join(KEYS_DIR, "registry.json")

# pem stem -> (operator name in crawler_registry.OPERATORS, keyid)
CRAWLERS = {
    "trainbot": ("trainbot.example", "trainbot-2026-10"),
    "searchbot": ("labsearch.example", "searchbot-2026-10"),
}


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _pem_path(stem: str) -> str:
    return os.path.join(KEYS_DIR, f"{stem}_ed25519.pem")


def _load_or_create(stem: str, force: bool) -> tuple[Ed25519PrivateKey, bool]:
    path = _pem_path(stem)
    if os.path.exists(path) and not force:
        with open(path, "rb") as fh:
            return serialization.load_pem_private_key(fh.read(), password=None), False
    key = Ed25519PrivateKey.generate()
    os.makedirs(KEYS_DIR, exist_ok=True)
    with open(path, "wb") as fh:
        fh.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                   serialization.NoEncryption()))
    return key, True


def main(force: bool = False) -> dict:
    """Create missing keys and (re)write registry.json. Returns the published keys."""
    published: dict[str, dict[str, str]] = {}
    for stem, (operator, keyid) in CRAWLERS.items():
        key, created = _load_or_create(stem, force)
        raw_pub = key.public_key().public_bytes(serialization.Encoding.Raw,
                                                serialization.PublicFormat.Raw)
        published.setdefault(operator, {})[keyid] = _b64url(raw_pub)
        rel = os.path.relpath(_pem_path(stem), LAB_DIR)
        print(f"{'wrote' if created else 'kept '} {rel}  ({keyid})")
    with open(REGISTRY_JSON, "w") as fh:
        json.dump(published, fh, indent=1)
    print(f"wrote {os.path.relpath(REGISTRY_JSON, LAB_DIR)}  (public keys for the registry)")
    return published


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--force", action="store_true", help="regenerate even if keys exist")
    main(parser.parse_args().force)
