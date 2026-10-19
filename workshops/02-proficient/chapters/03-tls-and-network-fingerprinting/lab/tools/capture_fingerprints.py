"""
W2 Ch3, Round 1 setup: record the HTTP libraries on *this* machine.

A library's JA4 depends on the TLS library it was built against: python.org macOS builds, Homebrew,
Debian and Alpine Pythons ship different OpenSSL versions and defaults. A denylist copied from
someone else's laptop (or a public list) misses yours. This script sends one request from each
library in round0_recon.LIBRARY_CLIENTS through the TLS edge and writes their JA4s to
defenses/local_fingerprints.json, which ja4.known() merges with the shipped list.

Production equivalent: label fingerprints from traffic you can attribute (your own monitoring,
partner integrations, confirmed abuse) instead of importing someone else's hashes.

Run (with the store and the edge up, any DEFENSE_LEVEL below 1, or before you wire Round 1):
    python tools/capture_fingerprints.py
The store picks the new file up on the next request (no restart).
"""

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "attacks"))

from round0_recon import LIBRARY_CLIENTS, collect  # noqa: E402

LOCAL_FILE = os.path.join(HERE, "..", "defenses", "local_fingerprints.json")


def main():
    found = {}
    for name, data in collect(LIBRARY_CLIENTS):
        if "error" in data or not data.get("ja4"):
            print(f"  ! {name}: {data.get('error', 'no JA4: is the edge running?')}")
            continue
        found[data["ja4"]] = f"{name} (captured on this machine)"
        print(f"  {name:<18} {data['ja4']}")
    if not found:
        return 1
    with open(LOCAL_FILE, "w") as f:
        json.dump({"library_ja4": found}, f, indent=2)
    print(f"\nWrote {len(found)} fingerprints to defenses/local_fingerprints.json.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
