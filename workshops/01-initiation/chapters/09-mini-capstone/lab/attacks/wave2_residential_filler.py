"""
W1 Ch9 — Wave 2: residential proxies and a generic form filler (beats Round 2).

The attacker read W1 Ch3. Cloud IPs are burned, so every attempt goes out
through a different address in a residential proxy network: real home
connections whose reputation is exactly as clean as your customers'.

Each attempt is a fresh client (new cookie jar, new IP): open the product
page, fill EVERY input the HTML contains, and submit at once. That is how
off-the-shelf form-filling bots work: they never run the page's JavaScript
and never look at the CSS.

Expected (tools/checkpoint.py):
  Round 2  takes most of the drop: IP reputation and headers see nothing
  Round 3  stopped: it fills the hidden honeypot field (100, a fake success:
           it still "believes" it bought hoodies), never runs the page script
           (no_js_cookie 20) and submits in milliseconds (form_too_fast 30)

    python attacks/wave2_residential_filler.py
"""

import json
import os
import random
import sys
import threading
from collections import Counter

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tools"))
from browsers import chrome  # noqa: E402
from labclient import BASE_URL, LabClient, form_fields, world_pool  # noqa: E402

ATTEMPTS = 60
THREADS = 10


def fill(fields, i):
    """Fill every field the way a generic filler does: by name, with plausible junk."""
    data = {}
    for name, value in fields.items():
        if value:
            data[name] = value                          # keep hidden values (csrf ...)
        elif "mail" in name:
            data[name] = f"res{i}@scalp.example"
        elif name == "size":
            data[name] = "M"
        elif name in ("website", "url", "homepage"):
            data[name] = "https://scalp.example"
        else:
            data[name] = "x"
    return data


def run(seed=2):
    pool = world_pool("residential_proxy")
    rng = random.Random(seed)
    lock, sold_out = threading.Lock(), threading.Event()
    totals = {"believed": 0, "requests": 0, "statuses": Counter()}
    attempts = list(range(ATTEMPTS))

    def worker():
        while not sold_out.is_set():
            with lock:
                if not attempts:
                    return
                i = attempts.pop(0)
                ip = rng.choice(pool)
            shop = LabClient("bot:wave2", ip=ip)           # fresh cookie jar, fresh IP
            page = shop.get("/drop", chrome(153, "windows", "typed", BASE_URL))
            believed = 0
            if page.status_code == 200:
                r = shop.post("/checkout", fill(form_fields(page.text), i),
                              chrome(153, "windows", "post", BASE_URL, BASE_URL + "/drop"))
                believed = r.status_code == 200 and "Order" in r.text
                if r.status_code == 410:
                    sold_out.set()
            with lock:
                totals["believed"] += believed
                totals["requests"] += shop.requests
                totals["statuses"].update(shop.statuses)

    threads = [threading.Thread(target=worker) for _ in range(THREADS)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return {"wave": "wave2", "believed": totals["believed"], "requests": totals["requests"],
            "statuses": dict(totals["statuses"]), "pow_seconds": 0.0, "browser_sessions": 0}


if __name__ == '__main__':
    result = run()
    if "--json" in sys.argv:
        print(json.dumps(result))
    else:
        print(f"=== Wave 2: residential proxies + form filler ===\n  believes it bought "
              f"{result['believed']} hoodies in {result['requests']} requests · statuses {result['statuses']}")
