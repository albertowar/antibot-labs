"""
Round 5: the client side of the proof-of-work gate. Shared by the solving crawler, the replay probe and
the cohort's browsers (tools/personas_ch3.py).

  * read the puzzle: from the gate's 403 interstitial (`<script id="pow-payload">`) or, on /api/ paths,
    from the JSON `challenge_required` error
  * solve it: the same hashcash puzzle as defenses/pow_core.py (find a counter so that
    SHA-256("<nonce>:<counter>") has `bits` leading zero bits), on one core
  * redeem it: POST the counter to /api/challenge/verify from the SAME address and cookie jar; the
    pass is the session cookie's clearance, and the server decides what it is worth

Real Anubis solves the puzzle in JavaScript, in the visitor's browser. The lab's clients are Python,
so the solver is Python: what matters for the economics is hashes, not the language.
"""

import json
import os
import re
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
LAB = os.path.abspath(os.path.join(HERE, ".."))
for p in (HERE, LAB):
    if p not in sys.path:
        sys.path.insert(0, p)

from defenses.pow_core import solve  # noqa: E402  (the puzzle is the same on both sides)

PAYLOAD = re.compile(r'<script type="application/json" id="pow-payload">(.*?)</script>', re.S)
# Rough on-demand price of one cloud vCPU-hour (W1 Ch7 uses the same figure). Spot capacity and botnets are cheaper.
USD_PER_VCPU_HOUR = 0.04


def payload_of(r):
    """The challenge in a gate 403, or None when this response is not a proof-of-work gate."""
    if r.status_code != 403:
        return None
    try:
        err = r.json().get("error", {})
        if err.get("code") == "challenge_required" and err.get("challenge") == "pow":
            return err["payload"]
        return None
    except ValueError:
        pass
    m = PAYLOAD.search(r.text)
    return json.loads(m.group(1)) if m else None


def solve_payload(payload, max_hashes=None):
    """-> (counter or None, hashes tried, CPU seconds spent)."""
    started = time.process_time()
    counter, tried = solve(payload["nonce"], int(payload["difficulty"]), max_hashes=max_hashes)
    return counter, tried, time.process_time() - started


def redeem(client, payload, counter, headers, ip=None):
    """POST the answer; True when the gate granted the session its pass."""
    r = client.post("/api/challenge/verify", json={"type": "pow", "answer": {"challenge": payload, "counter": counter}},
                    headers=[*headers, ("Content-Type", "application/json")], ip=ip)
    return r.status_code == 200
