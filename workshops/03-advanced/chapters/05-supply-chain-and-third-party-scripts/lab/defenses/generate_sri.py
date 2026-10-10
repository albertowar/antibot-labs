"""
generate_sri.py — DEFENSE (Round 3): pin the vendor file you trust.

Prints a <script> tag with a SHA-384 integrity attribute for each file you
explicitly include. The browser fetches the file, checks the hash, and refuses
to run it if the bytes differ — so a vendor who swaps the file ships a file the
browser will not execute.

Reads local files by default (the lab serves its vendor file from disk). Pass
URLs to hash a remote CDN file instead.

Limit to teach alongside this: SRI only covers files named in a <script> tag.
It cannot see a script injected at runtime by another script, and it will FAIL
CLOSED on a legitimate CDN version bump — budget for re-pinning on every
dependency update.

Prereqs:  pip install httpx   (only needed for URL targets)
Usage:
  python generate_sri.py                      # hash the lab's vendor baseline
  python generate_sri.py https://cdn/lib.js   # hash a remote file
"""

import base64
import hashlib
import os
import sys

HERE = os.path.dirname(__file__)
# The known-good baseline is what we pin; the served file is checked against it.
DEFAULT_TARGETS = [
    os.path.join(HERE, "..", "demo_site", "static", "vendor", "analytics-helper.baseline.js"),
]
SERVED_NAME = "/static/vendor/analytics-helper.js"


def sri(content: bytes) -> str:
    return "sha384-" + base64.b64encode(hashlib.sha384(content).digest()).decode()


def read_target(target: str) -> bytes:
    if target.startswith("http://") or target.startswith("https://"):
        import httpx
        resp = httpx.get(target, follow_redirects=True, timeout=15)
        resp.raise_for_status()
        return resp.content
    with open(target, "rb") as fh:
        return fh.read()


def main():
    targets = sys.argv[1:] or DEFAULT_TARGETS
    print("<!-- Pin these on the <script> tags in base.html -->\n")
    for target in targets:
        try:
            value = sri(read_target(target))
        except Exception as exc:  # noqa: BLE001 — surface any fetch/read error
            print(f"<!-- ERROR {target}: {exc} -->")
            continue
        src = SERVED_NAME if target in DEFAULT_TARGETS else target
        print(f'<script src="{src}"\n'
              f'        integrity="{value}"\n'
              f'        crossorigin="anonymous"></script>\n')


if __name__ == "__main__":
    main()
