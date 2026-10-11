"""
W4 Ch9 Capstone — Generate the lab's agent-operator keys and their key directories

Three operators, all local, all synthetic:

    agents.lab-provider.test   the operator the store TRUSTS (defenses/trusted_operators.json).
                               Its key signs the verified agent (Round 3) and the agent-user personas.
    agents.newvendor.test      a vendor that appears on launch day (Round 4). Honest, signed, unknown to
                               trusted_operators.json until someone onboards it.
    agents.evil.test           an operator that published a perfectly valid key directory of its own.
                               Nobody at the store has ever heard of it (Round 3's third case).

Writes data/keys/<name>.pem (private) and data/directories/<host>.json (what
the operator would serve at /.well-known/http-message-signatures-directory).

Plus the two crawler operators from defenses/crawler_registry.py (the L1 crawl
governance layer, from W4 Ch3):

    trainbot    LabTrainBot    keyid trainbot-2026-10
    searchbot   LabSearchBot   keyid searchbot-2026-10

Writes attacks/keys/<name>_ed25519.pem (private, used by tools/crawl.py) and
attacks/keys/registry.json (the public keys the registry loads).

Idempotent: existing keys are kept unless --force. Nothing here is committed
(data/keys/ and attacks/keys/ are gitignored): a private key in git, even a
synthetic one, trips secret scanners and teaches the wrong habit.

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

OPERATORS = {"lab-provider": "agents.lab-provider.test", "evil": "agents.evil.test",
             "newvendor": "agents.newvendor.test"}


# pem stem -> (operator name in crawler_registry.OPERATORS, keyid)
CRAWLERS = {"trainbot": ("trainbot.example", "trainbot-2026-10"),
            "searchbot": ("labsearch.example", "searchbot-2026-10")}
CRAWLER_KEYS = os.path.join(LAB_DIR, "attacks", "keys")


def key_path(name):
    return os.path.join(LAB_DIR, "data", "keys", f"{name}.pem")


def crawler_key_path(stem):
    return os.path.join(CRAWLER_KEYS, f"{stem}_ed25519.pem")


def make_crawler_keys(force=False):
    """The crawler operators' key pairs, published as attacks/keys/registry.json."""
    from cryptography.hazmat.primitives import serialization
    published = {}
    for stem, (operator, keyid) in CRAWLERS.items():
        pem = crawler_key_path(stem)
        if os.path.exists(pem) and not force:
            key = httpsig.load_private_key(pem)
            print(f"  kept   {os.path.relpath(pem, LAB_DIR)}")
        else:
            key = httpsig.generate_private_key()
            httpsig.save_private_key(key, pem)
            print(f"✅ wrote  {os.path.relpath(pem, LAB_DIR)}")
        raw = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        published.setdefault(operator, {})[keyid] = httpsig.b64url(raw)
    out = os.path.join(CRAWLER_KEYS, "registry.json")
    with open(out, "w") as f:
        json.dump(published, f, indent=1)
    print(f"✅ wrote  {os.path.relpath(out, LAB_DIR)}  (crawler public keys for defenses/crawler_registry.py)")
    return published


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
    make_crawler_keys(force)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    parser.add_argument("--force", action="store_true", help="regenerate even if keys exist")
    main(parser.parse_args().force)
