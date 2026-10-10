"""
W1 Ch9 — Wave 1: a fleet of cloud VMs with copied browser headers (beats Round 1).

The attacker read W1 Ch4. Every request now carries a full, correctly
ordered Chrome 153 header set with matching Client Hints (copied from
DevTools), so header scoring sees a browser. And instead of one VM it rents
40, each buying at most three hoodies: every per-IP and per-/24 bucket stays
nearly full.

Expected (tools/checkpoint.py):
  Round 1  takes most of the drop: rate limits and headers see nothing wrong
  Round 2  stopped: every VM sits in a published cloud range (datacenter 40)
           and most also in a hosting ASN (25). "Challenge", so a block.

    python attacks/wave1_cloud_fleet.py
"""

import json
import os
import sys
import threading
from collections import Counter

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tools"))
from browsers import chrome  # noqa: E402
from labnet import BASE_URL, LabClient, form_fields, world_pool  # noqa: E402

VMS = 40
PER_VM = 3
THREADS = 10


def one_vm(ip, i, totals, lock, sold_out):
    shop = LabClient("bot:wave1", ip=ip)
    believed = 0
    if shop.get("/", chrome(153, "windows", "typed", BASE_URL)).status_code == 200:
        page = shop.get("/drop", chrome(153, "windows", "link", BASE_URL, BASE_URL + "/"))
        if page.status_code == 200:
            csrf = form_fields(page.text).get("csrf", "")
            for n in range(PER_VM):
                if sold_out.is_set():
                    break
                r = shop.post("/checkout", {"csrf": csrf, "email": f"vm{i}.{n}@scalp.example", "size": "M"},
                              chrome(153, "windows", "post", BASE_URL, BASE_URL + "/drop"))
                if r.status_code == 410:
                    sold_out.set()
                believed += r.status_code == 200
                if r.status_code != 200:
                    break
    with lock:
        totals["believed"] += believed
        totals["requests"] += shop.requests
        totals["statuses"].update(shop.statuses)


def run():
    vms = world_pool("cloud_vm")[1:VMS + 1]
    totals, lock, sold_out = {"believed": 0, "requests": 0, "statuses": Counter()}, threading.Lock(), threading.Event()
    queue = list(enumerate(vms))

    def worker():
        while True:
            with lock:
                if not queue:
                    return
                i, ip = queue.pop(0)
            one_vm(ip, i, totals, lock, sold_out)

    threads = [threading.Thread(target=worker) for _ in range(THREADS)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return {"wave": "wave1", "believed": totals["believed"], "requests": totals["requests"],
            "statuses": dict(totals["statuses"]), "pow_seconds": 0.0, "browser_sessions": 0}


if __name__ == '__main__':
    result = run()
    if "--json" in sys.argv:
        print(json.dumps(result))
    else:
        print(f"=== Wave 1: {VMS} cloud VMs, copied Chrome headers ===\n  believes it bought "
              f"{result['believed']} hoodies in {result['requests']} requests · statuses {result['statuses']}")
