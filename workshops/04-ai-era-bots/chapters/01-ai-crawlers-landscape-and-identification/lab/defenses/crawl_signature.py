"""Round 3: does an unclaimed client behave like a crawler?

The stealth crawler claims nobody: a browser User-Agent from a rented cloud address.
Registry and verification have nothing to say. What it cannot hide is how it fetches.

features() is given. It turns one address's recent request history (plus one
collective signal) into numbers:

  n_requests, n_pages, n_assets   evidence so far (non-asset requests, pages, assets)
  asset_ratio        assets per page: browsers ~3 here (css + js + logo), parsers 0
  cadence_cv         coefficient of variation of gaps between pages: loops ~0, people ~1
  sitemap_order      share of consecutive product fetches in ascending SKU order
  cookie_continuity  share of pages sent with our session cookie
  coverage           distinct products fetched by this address / catalog size
  asn_class          isp / mobile / cloud / hosting / operator
  cluster_cov        catalog share fetched by ALL cookie-less clients sharing this
                     client's (User-Agent, ASN) pair, i.e. one crawler on many addresses
  robots_fetched     whether this address ever asked for /robots.txt

score(features) is yours: return (points, reasons). The store labels a browser-like
client "undeclared-crawler" at or above THRESHOLD. Two rules to keep:

  * Do not judge on thin evidence. Below MIN_EVIDENCE requests an address is not a
    crawler, it is a link preview, an uptime check or someone with curl. Scrapers
    must make many requests; previewers never do.
  * Collective signals may fire earlier than individual ones: a cluster that has
    already fetched a third of the catalog is a crawler whatever this address did.

Check the cost in tools/checkpoint.py: humans (including the two on cloud egress
addresses), the RSS reader, the link unfurler, the uptime monitor and the developer
with curl must all stay at 0 blocked.
"""

from __future__ import annotations

import statistics

MIN_EVIDENCE = 4        # non-asset requests from one address before we judge it
THRESHOLD = 60          # score at or above this = undeclared crawler
CLUSTER_TRIP = 0.35     # catalog share a cookie-less (UA, ASN) cluster may fetch


def features(history: list[dict], catalog_size: int, cluster_cov: float, asn_class: str) -> dict:
    pages = [h for h in history if h["kind"] == "page"]
    assets = [h for h in history if h["kind"] == "asset"]
    n_pages = len(pages)
    f = {"n_requests": sum(1 for h in history if h["kind"] != "asset"), "n_pages": n_pages,
         "n_assets": len(assets), "asn_class": asn_class, "cluster_cov": cluster_cov,
         "robots_fetched": any(h["kind"] == "robots" for h in history)}
    f["asset_ratio"] = len(assets) / n_pages if n_pages else 0.0
    gaps = [b["t"] - a["t"] for a, b in zip(pages, pages[1:])]
    if len(gaps) >= 2 and statistics.mean(gaps) > 0:
        f["cadence_cv"] = statistics.pstdev(gaps) / statistics.mean(gaps)
    else:
        f["cadence_cv"] = None
    skus = [p["sku"] for p in pages if p.get("sku")]
    f["coverage"] = len(set(skus)) / catalog_size if catalog_size else 0.0
    pairs = list(zip(skus, skus[1:]))
    f["sitemap_order"] = (sum(1 for a, b in pairs if b > a) / len(pairs)) if pairs else None
    f["cookie_continuity"] = (sum(1 for p in pages if p["cookie"]) / n_pages) if n_pages else 0.0
    return f


def score(f: dict) -> tuple[float, list[str]]:
    # TODO (Round 3): add points per signal and return (score, reasons).
    #   Suggested starting weights (tune them against the checkpoint):
    #     cluster_cov >= CLUSTER_TRIP and no cookies    +50  (may fire before MIN_EVIDENCE)
    #     --- below here only when n_requests >= MIN_EVIDENCE ---
    #     asset_ratio < 0.5                             +30
    #     cadence_cv < 0.25                             +20
    #     sitemap_order >= 0.9                          +20
    #     cookie_continuity < 0.2                       +15
    #     coverage >= 0.25                              +25
    #     asn_class in (cloud, hosting)                 +15
    #   Ask of every weight: which real client could it hurt, and is it enough on its
    #   own to cross THRESHOLD? A Private Relay user is "cloud" and nothing else.
    return 0.0, []
