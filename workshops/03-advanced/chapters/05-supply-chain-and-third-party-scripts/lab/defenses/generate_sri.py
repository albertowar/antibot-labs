"""
generate_sri.py: pin the vendor file you trust (Round 3, level 3).

The browser fetches a <script integrity="sha384-..."> file, checks the hash and refuses to run it if
the bytes differ, so a vendor who swaps the file ships a file the browser will not execute. This
module is both halves:

  CHECK   the ladder check: the vendor <script> carries the pin (page.sri)
  CLI     prints the <script> tag for a file you explicitly include

The pin is a promise about ONE known-good file: the lab pins the baseline release in
demo_site/ext/assets/analytics-helper.baseline.js and the store may be serving something else.

Limits to teach alongside this: SRI only covers files named in a <script> tag. It cannot see a script
injected at runtime by another script, and it cannot see your own bundle being poisoned (you would
pin the poisoned build). It FAILS CLOSED on a legitimate CDN version bump: the new, good file is
refused for every user until you re-pin and redeploy (`tools/cdn_bump.py` measures it).

Usage:
  python -m defenses.generate_sri                       # hash the lab's known-good vendor file
  python -m defenses.generate_sri https://cdn/lib.js    # hash a remote file (needs httpx)
"""

import base64
import hashlib
import os
import sys

from .pipeline import Check

HERE = os.path.dirname(os.path.abspath(__file__))
BASELINE = os.path.join(HERE, "..", "demo_site", "ext", "assets", "analytics-helper.baseline.js")
SERVED_NAME = "/static/vendor/analytics-helper.js"


def sri(content: bytes) -> str:
    return "sha384-" + base64.b64encode(hashlib.sha384(content).digest()).decode()


def pin() -> str:
    """The integrity value the store puts on the vendor tag: the known-good baseline's hash."""
    with open(BASELINE, "rb") as fh:
        return sri(fh.read())


def _check(page):
    page.sri = pin()


CHECK = Check("sri", _check, phases=("page",))


def read_target(target: str) -> bytes:
    if target.startswith(("http://", "https://")):
        import httpx
        resp = httpx.get(target, follow_redirects=True, timeout=15)
        resp.raise_for_status()
        return resp.content
    with open(target, "rb") as fh:
        return fh.read()


def main(argv):
    targets = argv or [BASELINE]
    print("<!-- Pin these on the <script> tags (the store's template does it from the baseline file) -->\n")
    for target in targets:
        try:
            value = sri(read_target(target))
        except Exception as exc:  # noqa: BLE001  (surface any fetch/read error)
            print(f"<!-- ERROR {target}: {exc} -->")
            continue
        src = SERVED_NAME if target == BASELINE else target
        print(f'<script src="{src}"\n        integrity="{value}"\n        crossorigin="anonymous"></script>\n')


if __name__ == "__main__":
    main(sys.argv[1:])
