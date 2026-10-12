"""
W1 Ch8 — Wave 0: the naive scalper (beats Round 0).

One rented cloud VM, python-requests with its default headers, and a loop:
load the form once, then submit it as fast as the store answers until the
hoodies are gone. Most first-week scalping bots look exactly like this.

Expected (tools/checkpoint.py):
  Round 0  takes the whole drop before the first shopper reaches the form
  Round 1  stopped: python-requests UA (40) + no Accept-Language (15) +
           Accept */* (10) = 65, "challenge". With no challenge yet, a block.
           Pushed harder, the checkout_ip bucket stops it too.

    python attacks/wave0_naive_scalper.py
"""

import json
import os
import sys
from collections import Counter

import requests

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tools"))
from labclient import LabClient, form_fields, world_pool  # noqa: E402

MAX_ATTEMPTS = 60


def run():
    shop = LabClient("bot:wave0", ip=world_pool("cloud_vm")[0])
    library_defaults = list(requests.utils.default_headers().items())   # python-requests/2.x, */* ...
    page = shop.get("/drop", library_defaults)
    believed, outcomes = 0, Counter()
    if page.status_code == 200:
        csrf = form_fields(page.text).get("csrf", "")
        misses = 0
        for i in range(MAX_ATTEMPTS):
            r = shop.post("/checkout", {"csrf": csrf, "email": f"drop{i}@scalp.example", "size": "M"},
                          library_defaults)
            outcomes[r.status_code] += 1
            if r.status_code == 200:
                believed += 1
                misses = 0
            elif r.status_code == 410:
                break
            else:
                misses += 1
                if misses >= 3:
                    break
    else:
        outcomes[page.status_code] += 1
    return {"wave": "wave0", "believed": believed, "requests": shop.requests,
            "statuses": dict(Counter(shop.statuses)), "pow_seconds": 0.0, "browser_sessions": 0}


if __name__ == '__main__':
    result = run()
    if "--json" in sys.argv:
        print(json.dumps(result))
    else:
        print(f"=== Wave 0: naive scalper ===\n  believes it bought {result['believed']} hoodies "
              f"in {result['requests']} requests · statuses {result['statuses']}")
