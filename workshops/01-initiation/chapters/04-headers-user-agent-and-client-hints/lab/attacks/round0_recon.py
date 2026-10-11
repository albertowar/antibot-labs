"""
Chapter 4, Round 0: what does each client actually send?

Objective: before attacking or defending anything, look at the raw material. Send the same request
to /lab/headers/check with three clients and compare the header names, values and ORDER the store
receives. The store echoes the headers in arrival order, with the lab's own X-Lab-* headers removed.

    python attacks/round0_recon.py

Then open http://127.0.0.1:5000/ and http://127.0.0.1:5000/lab/headers/check in Chrome and Firefox
and compare with what this prints. (urllib and curl reach the store without the lab headers, so the
store sees them from the default student address. Header checks do not care.)
"""

import json
import os
import shutil
import subprocess
import sys
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tools"))
from headers_client import BASE_URL, bot  # noqa: E402

CHECK = "/lab/headers/check"


def show(label, payload):
    names = [n for n, _ in payload["headers_received"]]
    print(f"=== {label}: {len(names)} headers ===")
    for name, value in payload["headers_received"]:
        print(f"  {name}: {value}")
    print()
    return names


def via_requests():
    from headers_client import requests_defaults
    return show("python-requests (its defaults)", bot("recon").get(CHECK, requests_defaults()).json())


def via_urllib():
    with urllib.request.urlopen(BASE_URL + CHECK, timeout=10) as r:
        return show("urllib (stdlib)", json.loads(r.read()))


def via_curl():
    if not shutil.which("curl"):
        print("=== curl === (not installed, skipping)\n")
        return None
    out = subprocess.run(["curl", "-s", BASE_URL + CHECK], capture_output=True, text=True, timeout=10)
    return show("curl (defaults)", json.loads(out.stdout))


def run():
    seen = {"requests": via_requests(), "urllib": via_urllib(), "curl": via_curl()}
    seen = {k: v for k, v in seen.items() if v}
    return {"name": "round0_recon", "attempted": len(seen), "succeeded": len(seen),
            "headers": {k: len(v) for k, v in seen.items()}}


if __name__ == "__main__":
    result = run()
    print(f"Now open {BASE_URL}{CHECK} in Chrome and Firefox.")
    print("Questions: which headers do browsers add? In which order? What does Chrome send that Firefox does not?")
    print(json.dumps(result))
