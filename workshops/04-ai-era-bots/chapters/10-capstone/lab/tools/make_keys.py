"""
W4 Ch10 Capstone — generate the operators' signing keys and their key directories

Four synthetic operators sign requests in this lab:

    trainbot.example             the licensed training crawler (pays the RSL price)
    labsearch.example            the search crawler the reservation protects
    agents.lab-provider.test     the trusted shopping-agent vendor (mandated checkouts)
    agents.newvendor.test        a NEW vendor: its directory exists from day one, but the
                                 store does not trust it until Round 4's onboarding

Each gets an Ed25519 key pair: the private half in instance/keys/<name>.key (hex seed,
gitignored — a private key in git, even synthetic, trips secret scanners and teaches the
wrong habit), and the public half as a SIGNED key directory in
instance/keys/<authority>.json — `{"jwks": …, "headers": …}`, the JWK Set plus the
origin-binding signature headers it would have been served with
(defenses/key_directory.py reads these files; defenses/web_bot_auth.py verifies them).

The attacker's own origin (attacker.example) gets a pair too: Round 2's dark cloud agent
signs correctly with a key its own origin publishes — a VALID signature from an origin
the store does not trust, which is exactly the lesson.

    python tools/make_keys.py            # create any missing key (seed.py runs this)
    python tools/make_keys.py --force    # rotate: replace every key
"""

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
LAB = os.path.dirname(HERE)
sys.path.insert(0, LAB)

from defenses import httpsig  # noqa: E402

KEYS = os.path.join(LAB, "instance", "keys")
OPERATORS = {
    "trainbot.example": "https://trainbot.example",
    "labsearch.example": "https://labsearch.example",
    "agents.lab-provider.test": "https://agents.lab-provider.test",
    "agents.newvendor.test": "https://agents.newvendor.test",
    "attacker.example": "https://attacker.example",
}


def key_path(name):
    return os.path.join(KEYS, f"{name}.key")


def load_signer(name):
    """(private_key, keyid) for an operator; generates the pair on first use."""
    make(force=False, only=name)
    with open(key_path(name)) as fh:
        seed = fh.read().strip()
    private = httpsig.load_private(seed)
    jwk = httpsig.jwk_from_public(private.public_key())
    return private, httpsig.thumbprint(jwk)


# A lab session may run long after the keys were first generated, so the signed directory
# carries a generous validity window and is re-signed on every make() (store start / seed):
# the private key stays put, so signers and verifiers always agree, and the directory
# signature is never stale. (Request signatures still use httpsig's short default window.)
DIRECTORY_TTL = 30 * 24 * 3600


def make(force=False, only=None):
    os.makedirs(KEYS, exist_ok=True)
    made = []
    for name, origin in OPERATORS.items():
        if only and name != only:
            continue
        kp = key_path(name)
        authority = origin.removeprefix("https://")
        dirp = os.path.join(KEYS, f"{authority}.json")
        fresh_key = force or not os.path.exists(kp)
        if fresh_key:
            with open(kp, "w") as fh:
                fh.write(os.urandom(32).hex() + "\n")
        private = httpsig.load_private(open(kp).read().strip())
        jwk = httpsig.jwk_from_public(private.public_key())
        jwks = {"keys": [jwk]}
        headers = httpsig.sign_directory(jwks, {httpsig.thumbprint(jwk): private}, authority,
                                         ttl=DIRECTORY_TTL)
        with open(dirp, "w") as fh:
            json.dump({"jwks": jwks, "headers": headers}, fh, indent=1)
        if fresh_key:
            made.append(name)
    return made


if __name__ == "__main__":
    made = make(force="--force" in sys.argv)
    print(f"keys under {os.path.relpath(KEYS)}: " + (", ".join(made) if made else "all present"))
