"""Generate the lab's Ed25519 keypairs at setup. Nothing secret is committed.

    python tools/make_keys.py            # create any missing key (what every tool does on first use)
    python tools/make_keys.py --force    # rotate: replace both keys

Two synthetic owners need a key. The mock internet plays the *operator* (`chatgpt.com`: it signs
the key directory and the "leaked" requests), the genuine ChatGPT agent in the cohort signs with
the same key, and the Round 4 attacker (`attacker.example`) signs with its own. None of them
exist outside this lab, and none are committed: they are written to `tools/fixtures/keys/`
(gitignored) the first time anything asks for them, and a fresh clone gets fresh keys. The
checkpoints never print a thumbprint, so rotating changes no expected result.

In production the private key never leaves the operator's signing service. Here it sits in a file
on your disk because the lab has to play both ends; do not reuse it anywhere.

Other code asks for a key with `load(owner)`; it creates the file if it is missing.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))          # lab root: defenses/
from defenses import httpsig  # noqa: E402

KEYS_DIR = os.path.join(HERE, "fixtures", "keys")
OWNERS = ["chatgpt.com", "attacker.example"]


def _path(owner: str) -> str:
    return os.path.join(KEYS_DIR, f"{owner}.json")


def create(owner: str) -> dict:
    """Write a fresh keypair for `owner` (atomically: two processes may race on first use)."""
    seed, jwk, kid = httpsig.generate()
    doc = {"owner": owner, "seed_hex": seed, "jwk": jwk, "thumbprint": kid}
    os.makedirs(KEYS_DIR, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=KEYS_DIR, suffix=".tmp")
    with os.fdopen(fd, "w") as fh:
        json.dump(doc, fh, indent=2)
    os.chmod(tmp, 0o600)
    os.replace(tmp, _path(owner))
    return doc


def load(owner: str) -> dict:
    """{"owner", "seed_hex", "jwk", "thumbprint"} for `owner`, creating the key on first use."""
    try:
        with open(_path(owner)) as fh:
            return json.load(fh)
    except (FileNotFoundError, ValueError):
        create(owner)
        with open(_path(owner)) as fh:     # re-read: if another process won the race, use its key
            return json.load(fh)


def ensure() -> None:
    for owner in OWNERS:
        load(owner)


def main() -> None:
    force = "--force" in sys.argv
    for owner in OWNERS:
        existed = os.path.exists(_path(owner))
        doc = create(owner) if force else load(owner)
        state = "rotated" if force and existed else ("kept" if existed and not force else "created")
        print(f"{owner:18} {state:8} keyid={doc['thumbprint']}  -> {os.path.relpath(_path(owner))}")


if __name__ == "__main__":
    main()
