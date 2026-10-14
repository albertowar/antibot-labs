"""
Round 1 attack (beats rate limits and headers): a fleet of cloud VMs with copied browser headers.

The attacker read W1 Ch4. Every request now carries a full, correctly ordered Chrome 153 header set
with matching Client Hints (copied from DevTools), so header scoring sees a browser. And instead of
one VM it rents 40, each buying at most three hoodies: every per-IP bucket stays nearly full.

Expected (tools/checkpoint.py):
  Round 1  takes most of the drop: rate limits and headers see nothing wrong
  Round 2  stopped: every VM sits in a published cloud range (datacenter 40) and most also in a
           hosting ASN (25): the challenge band, which is a block until Round 4

    python attacks/round1_cloud_fleet.py
"""

import threading

import _drop as d
from labclient import BASE_URL, LabClient, world_pool

VMS = 40
PER_VM = 3
THREADS = 10


def one_vm(ip, i, tally, lock, sold_out):
    shop = LabClient("bot:r1_fleet", ip=ip)
    believed, attempts = 0, 0
    if shop.get("/", d.chrome("typed")).status_code == 200:
        page = shop.get(d.PATH, d.chrome("link", BASE_URL + "/"))
        if page.status_code == 200:
            fields = d.parse_form(page.text)
            for n in range(PER_VM):
                if sold_out.is_set():
                    break
                attempts += 1
                r = shop.post(d.PATH, d.fill(fields, f"vm{i}.{n}@scalp.example"), d.chrome("post", BASE_URL + d.PATH))
                if r.status_code == 410:
                    sold_out.set()
                if not d.bought(r):
                    break
                believed += 1
    with lock:
        tally.believed += believed
        tally.attempted += attempts
        tally.count(shop)


def run():
    tally, lock, sold_out = d.Tally("round1_cloud_fleet"), threading.Lock(), threading.Event()
    queue = list(enumerate(world_pool("cloud_vm")[1:VMS + 1]))

    def worker():
        while True:
            with lock:
                if not queue:
                    return
                i, ip = queue.pop(0)
            one_vm(ip, i, tally, lock, sold_out)

    threads = [threading.Thread(target=worker) for _ in range(THREADS)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return tally


if __name__ == "__main__":
    d.finish(f"Round 1: {VMS} cloud VMs, copied Chrome headers", run())
