"""
Round 2 attack (beats IP reputation): residential proxies and a generic form filler.

The attacker read W1 Ch3. Cloud IPs are burned, so every attempt goes out through a different address
in a residential proxy network (six countries, one address per /64): real home connections whose
reputation is exactly as clean as your customers'.

Each attempt is a fresh client (new cookie jar, new address): open the drop page, fill EVERY input the
HTML contains, and submit at once. That is how off-the-shelf form-filling bots work: they never run the
page's JavaScript and never look at the CSS.

Expected (tools/checkpoint.py):
  Round 2  takes most of the drop: IP reputation and headers see nothing wrong
  Round 3  stopped: it fills the hidden honeypot (100, answered with a fake success, so the bot still
           "believes" it bought), never loaded the home page or ran the page script, and posts in
           milliseconds (the timing token)

    python attacks/round2_residential_filler.py
"""

import random
import threading

import _drop as d
from labclient import BASE_URL, LabClient, world_pool

ATTEMPTS = 60
THREADS = 10


def run(seed=2):
    tally, lock, sold_out = d.Tally("round2_residential_filler"), threading.Lock(), threading.Event()
    pool, rng = world_pool("residential_proxy_net"), random.Random(seed)
    attempts = list(range(ATTEMPTS))

    def worker():
        while not sold_out.is_set():
            with lock:
                if not attempts:
                    return
                i, ip = attempts.pop(0), rng.choice(pool)
            shop = LabClient("bot:r2_filler", ip=ip)               # fresh cookie jar, fresh address
            page = shop.get(d.PATH, d.chrome("typed"))
            believed = tried = 0
            if page.status_code == 200:
                tried = 1
                r = shop.post(d.PATH, d.fill(d.parse_form(page.text), f"res{i}@scalp.example", junk="https://scalp.example"),
                              d.chrome("post", BASE_URL + d.PATH))
                believed = d.bought(r)
                if r.status_code == 410:
                    sold_out.set()
            with lock:
                tally.believed += believed
                tally.attempted += tried
                tally.count(shop)

    threads = [threading.Thread(target=worker) for _ in range(THREADS)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return tally


if __name__ == "__main__":
    d.finish("Round 2: residential proxies + a form filler", run())
