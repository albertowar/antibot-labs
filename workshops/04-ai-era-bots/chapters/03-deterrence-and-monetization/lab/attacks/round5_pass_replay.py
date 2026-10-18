"""Round 5 attack: make one pass go further than it was sold for.

A pass that is a bearer cookie is a ticket. Anubis's well-known weakness is exactly that: solve once,
then reuse the cookie for as long as it lives, from wherever you like. The gate narrows the pass
(address binding, a page budget, a lifetime); this script probes the first two, cheaply (the third
is a 120-second wait):

  probe 1  earn a pass from one address, then present the cookie from ANOTHER address
           (the move of a crawler that solves once and then rotates addresses, or sells passes)
  probe 2  earn a pass and spend it past its budget (POW_PASS_BUDGET + 1 protected requests)

`succeeded` counts the probes that got a product record for free; `attempted` is 2. A gate that
holds both answers 0/2.

    python attacks/round5_pass_replay.py
"""

from __future__ import annotations

import json

from _common import CHROME_UA
import pow_client
from labclient import LabClient, world_pool

HEADERS = [("User-Agent", CHROME_UA), ("Accept", "text/html,*/*;q=0.8")]
JSON_HEADERS = [("User-Agent", CHROME_UA), ("Accept", "application/json")]
A, B = world_pool("residential_proxy")[120:122]


def earn(client, ip):
    """Get a pass for `ip`: ask for a product, solve the 403, redeem. Returns the hashes it cost."""
    r = client.get("/product/p001", HEADERS, ip=ip)
    payload = pow_client.payload_of(r)
    if payload is None:
        return 0                                     # no gate at this level: nothing to earn
    counter, tried, _ = pow_client.solve_payload(payload)
    assert pow_client.redeem(client, payload, counter, JSON_HEADERS, ip=ip), "the gate refused a correct answer"
    return tried


def run():
    notes, hashes = {}, 0
    # probe 1: the pass earned at A, shown at B
    c = LabClient("bot:replay:00", ip=A)
    hashes += earn(c, A)
    notes["at_A"] = c.get("/product/p002", HEADERS, ip=A).status_code
    notes["moved_to_B"] = (moved := c.get("/product/p003", HEADERS, ip=B)).status_code
    # probe 2: a fresh pass at A, spent past its budget
    c = LabClient("bot:replay:01", ip=A)
    hashes += earn(c, A)
    from defenses import policy
    codes = [c.get(f"/product/p{i:03d}", HEADERS, ip=A).status_code for i in range(10, 10 + policy.POW_PASS_BUDGET + 1)]
    notes["budget"] = policy.POW_PASS_BUDGET
    notes["over_budget_last"] = codes[-1]
    notes["served_before_last"] = sum(code == 200 for code in codes[:-1])
    free = int(moved.status_code == 200) + int(codes[-1] == 200)
    out = {"label": "pass replay", "attempted": 2, "succeeded": free, "hashes": hashes, **notes}
    print(f"[replay] probe 1 (cookie carried to another address): HTTP {notes['moved_to_B']}; "
          f"probe 2 ({notes['budget']} requests served, then request {notes['budget'] + 1}): HTTP {notes['over_budget_last']}")
    print(json.dumps(out))
    return out


if __name__ == "__main__":
    run()
