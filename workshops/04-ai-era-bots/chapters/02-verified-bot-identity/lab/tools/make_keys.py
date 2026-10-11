"""Generate the lab's Ed25519 keypairs (synthetic operators and the attacker).

    python tools/make_keys.py          # rewrites tools/fixtures/keys/*.json

The private seeds are committed on purpose: the mock internet plays the operator
(it must sign leaked requests and its key directory), the legitimate simulator
plays the genuine ChatGPT agent, and the Round 4 attacker plays itself. None of
these keys exist outside this lab. In production the private key never leaves the
operator's signing service, which is the whole point of the scheme.
"""

from __future__ import annotations

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "defenses"))
import httpsig  # noqa: E402

KEYS_DIR = os.path.join(HERE, "fixtures", "keys")
OWNERS = ["chatgpt.com", "attacker.example"]


def main():
    os.makedirs(KEYS_DIR, exist_ok=True)
    for owner in OWNERS:
        seed, jwk, kid = httpsig.generate()
        path = os.path.join(KEYS_DIR, f"{owner}.json")
        with open(path, "w") as fh:
            json.dump({"owner": owner, "seed_hex": seed, "jwk": jwk, "thumbprint": kid}, fh, indent=2)
        print(f"{owner:18} keyid={kid}  -> {os.path.relpath(path)}")


if __name__ == "__main__":
    main()
