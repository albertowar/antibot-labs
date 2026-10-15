"""
Round 1 attack: REST scraping with oversized pages and an id walk.

Two classic moves against the store's API, from a datacenter address with a script User-Agent:

  * **id enumeration** - hit ``/api/products/p001``, ``p002``, ``p003`` ... in order, the whole catalogue one
    detail page at a time.
  * **bulk export** - ask for the biggest page the endpoint will give (``/api/v2/reviews?limit=200``) and walk
    every page: the whole review corpus in a handful of requests.

At DEFENSE_LEVEL=0 both drain the store in seconds. At level 1 the cost-aware limiter stops the sequential walk
after a handful of ids and refuses the oversized pages. The attack is deliberately just strong enough to drain
the data and trip the detector: it is a teaching tool against your own local store, not a general scraper.

    python attacks/round1_scrape.py
"""

import math

from _common import SCRIPT_UA, ApiApp, bot_ip, finish

ACTOR = "bot:r1_scrape"
PAGE = 200
SKUS = 120


def run():
    app = ApiApp(ACTOR, bot_ip(0), ua=SCRIPT_UA)
    got_reviews = got_products = refused = 0
    for n in range(1, SKUS + 1):                                  # the id walk, one detail page at a time
        r = app.get(f"/api/products/p{n:03d}")
        if r.status_code == 200:
            got_products += 1
        else:
            refused += 1
    probe = app.get("/api/v2/reviews?limit=1")                   # then the bulk export: how big is the corpus?
    total = probe.json().get("total", 0) if probe.status_code == 200 else 600
    for page in range(1, math.ceil(total / PAGE) + 1):
        r = app.get(f"/api/v2/reviews?limit={PAGE}&page={page}")
        if r.status_code == 200:
            got_reviews += len(r.json()["items"])
        else:
            refused += 1
    return finish("round1_scrape", total + SKUS, got_reviews + got_products, "records scraped",
                  reviews=got_reviews, products=got_products, refused=refused, requests=app.client.requests,
                  last_verdict=app.client.verdict())


if __name__ == "__main__":
    run()
