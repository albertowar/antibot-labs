"""Generate the lab's Ed25519 keypairs at setup. Nothing secret is committed.

    python tools/make_keys.py            # create any missing key (what every tool does on first use)
    python tools/make_keys.py --force    # rotate: replace both keys

Two synthetic agent operators need a key: `agents.lab-provider.test` (the operator the store trusts:
its key signs the verified agent of Round 3 and the people's agents of Round 4) and `agents.evil.test`
(an operator that published a perfectly valid key directory of its own, which nobody at the store has
ever heard of: Round 3's third forgery). The mock internet plays their websites: it publishes each
operator's signed key directory, and the agent scripts sign their requests with the matching private
key. Neither operator exists outside this lab (`.test` is reserved, RFC 6761),
and no key is committed: they are written to `tools/fixtures/keys/` (gitignored) the first time
anything asks for them, and a fresh clone gets fresh keys. No checkpoint prints a thumbprint, so
rotating changes no expected result.

In production the private key never leaves the operator's signing service. Here it sits in a file on
your disk because the lab has to play both ends; do not reuse it anywhere.

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
OWNERS = ["agents.lab-provider.test", "agents.evil.test"]


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
        print(f"{owner:26} {state:8} keyid={doc['thumbprint']}  -> {os.path.relpath(_path(owner))}")


if __name__ == "__main__":
    main()
