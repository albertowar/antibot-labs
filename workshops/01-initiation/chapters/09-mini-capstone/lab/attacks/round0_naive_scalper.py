"""
Round 0 attack (beats the undefended store): the naive scalper.

One rented cloud VM, python-requests with its default headers, and a loop: load the drop page once,
then submit the form as fast as the store answers until the hoodies are gone. Most first-week
scalping bots look exactly like this.

Expected (tools/checkpoint.py):
  Round 0  takes the whole drop before the first shopper reaches the form
  Round 1  stopped: python-requests UA (40) plus the missing Accept-Language and the */* Accept
           push it past the block line; the drop POST bucket would stop it too

    python attacks/round0_naive_scalper.py
"""

import _drop as d
from labclient import LabClient, world_pool

MAX_ATTEMPTS = 60


def run():
    tally = d.Tally("round0_naive_scalper")
    shop = LabClient("bot:r0_scalper", ip=world_pool("cloud_vm")[0])
    page = shop.get(d.PATH, d.library_headers())
    if page.status_code == 200:
        fields, misses = d.parse_form(page.text), 0
        for i in range(MAX_ATTEMPTS):
            tally.attempted += 1
            r = shop.post(d.PATH, d.fill(fields, f"drop{i}@scalp.example"), d.library_headers())
            if d.bought(r):
                tally.believed, misses = tally.believed + 1, 0
            elif r.status_code == 410:
                break                                   # sold out
            else:
                misses += 1
                if misses >= 3:
                    break                               # three refusals in a row: it gives up
    tally.count(shop)
    return tally


if __name__ == "__main__":
    d.finish("Round 0: the naive scalper", run())
