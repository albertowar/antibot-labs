"""
Chapter 4 — Round 0 Recon: What Does Each Client Actually Send? (Section 4.1)

Objective: before attacking or defending anything, look at the raw material.
Hit the /header-check echo endpoint with three different clients and compare
the header names, values and ORDER the server receives.

Then open http://localhost:5000/ and http://localhost:5000/header-check in
Chrome and Firefox and compare with the output below.

Run the demo site first:
    cd demo_site && DEFENSE_LEVEL=0 python app.py
Then run:
    python attacks/round0_recon.py
"""

import json
import os
import shutil
import subprocess
import urllib.request

import requests

BASE_URL = os.environ.get("DEMO_URL", "http://localhost:5000")
CHECK_URL = f"{BASE_URL}/header-check"


def show(label, payload):
    print(f"=== {label} ===")
    for name, value in payload["headers_received"]:
        print(f"  {name}: {value}")
    print()


def via_requests():
    show("python-requests (defaults)", requests.get(CHECK_URL, timeout=5).json())


def via_urllib():
    with urllib.request.urlopen(CHECK_URL, timeout=5) as r:
        show("urllib (stdlib)", json.loads(r.read()))


def via_curl():
    if not shutil.which("curl"):
        print("=== curl === (not installed, skipping)\n")
        return
    out = subprocess.run(["curl", "-s", CHECK_URL], capture_output=True, text=True, timeout=5)
    show("curl (defaults)", json.loads(out.stdout))


if __name__ == '__main__':
    via_requests()
    via_urllib()
    via_curl()
    print(f"Now open {CHECK_URL} in Chrome and Firefox.")
    print("Questions: which headers do browsers add? In which order? What does Chrome send that Firefox doesn't?")
