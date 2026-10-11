"""
W4 Ch4 — Generate the lab's agent-operator keys and their key directories

Two operators, both local, both synthetic:

    agents.lab-provider.test   the operator the store TRUSTS (defenses/trusted_operators.json).
                               Its key signs the verified agent (Round 3) and the agent-user personas.
    agents.evil.test           an operator that published a perfectly valid key directory of its own.
                               Nobody at the store has ever heard of it (Round 3's third case).

Writes data/keys/<name>.pem (private) and data/directories/<host>.json (what
the operator would serve at /.well-known/http-message-signatures-directory).
Idempotent: existing keys are kept unless --force.

Run (from lab/):
    python tools/make_keys.py
"""

import argparse
import json
import os
import sys

LAB_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(LAB_DIR, "defenses"))
import httpsig  # noqa: E402

OPERATORS = {"lab-provider": "agents.lab-provider.test", "evil": "agents.evil.test"}


def key_path(name):
    return os.path.join(LAB_DIR, "data", "keys", f"{name}.pem")


def main(force=False):
    for name, host in OPERATORS.items():
        pem = key_path(name)
        if os.path.exists(pem) and not force:
            key = httpsig.load_private_key(pem)
            print(f"  kept   {os.path.relpath(pem, LAB_DIR)}")
        else:
            key = httpsig.generate_private_key()
            httpsig.save_private_key(key, pem)
            print(f"✅ wrote  {os.path.relpath(pem, LAB_DIR)}")
        directory = httpsig.directory_for(key)
        out = os.path.join(httpsig.DIRECTORIES, f"{host}.json")
        os.makedirs(httpsig.DIRECTORIES, exist_ok=True)
        with open(out, "w") as f:
            json.dump(directory, f, indent=1)
        print(f"✅ wrote  {os.path.relpath(out, LAB_DIR)}  (kid {directory['keys'][0]['kid'][:16]}…)")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    parser.add_argument("--force", action="store_true", help="regenerate even if keys exist")
    main(parser.parse_args().force)
