"""Round 3 (reference solution): does an unclaimed client behave like a crawler?

The stealth crawler of Round 2 claims nobody. It sends a browser User-Agent from a
rented cloud address, so neither the registry nor verification has anything to say.
What it cannot hide is *how* it fetches. From this address's own request history
(up to 15 minutes) and one collective signal, we compute:

  asset_ratio        assets fetched per page. Browsers load CSS, JS and images with
                     every page; HTML-only clients are parsers.
  cadence_cv         coefficient of variation of the gaps between page requests.
                     People are bursty; loops are metronomes.
  sitemap_order      share of consecutive product fetches in ascending SKU order.
                     Sitemap walkers go p001, p002, ...; shoppers do not.
  cookie_continuity  share of page requests carrying our session cookie. Browsers keep
                     it; stateless fetchers drop it.
  coverage           distinct products this address fetched / catalog size.
  asn_class          cloud / hosting addresses are where crawlers are rented.
  cluster_cov        catalog share fetched by all cookie-less clients sharing this
                     client's (User-Agent, ASN) pair. One crawler spread over thirty
                     addresses is still one client on one network.

score() adds points per signal and THRESHOLD turns the sum into a verdict. The
evidence gate matters as much as the weights: a client with fewer than MIN_EVIDENCE
requests is not scored at all. A link previewer, an uptime check or a developer with
curl never makes enough requests to be judged, and does not need to be. A crawler has
to, because it wants the whole catalog.

Where it fails (on purpose, see Round 3's evolved attacks): a crawler that fetches
assets, jitters, follows links, holds cookies and spreads itself over residential
addresses scores like a person. At the HTTP level that is the end of the road; W4 Ch2
makes the good ones prove who they are and W4 Ch3 makes the rest pay for every page.
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
    reasons: list[str] = []
    s = 0.0
    # Collective evidence first: a cluster can be judged before any one address can.
    if f["cluster_cov"] >= CLUSTER_TRIP and f["cookie_continuity"] < 0.2:
        s += 50
        reasons.append("distributed crawl cluster")
    if f["n_requests"] < MIN_EVIDENCE:
        return s, reasons or ["not enough evidence"]
    if f["asset_ratio"] < 0.5:
        s += 30
        reasons.append("html-only")
    if f["cadence_cv"] is not None and f["cadence_cv"] < 0.25:
        s += 20
        reasons.append("metronome cadence")
    if f["sitemap_order"] is not None and f["sitemap_order"] >= 0.9:
        s += 20
        reasons.append("walks catalog in sitemap order")
    if f["cookie_continuity"] < 0.2:
        s += 15
        reasons.append("no session continuity")
    if f["coverage"] >= 0.25:
        s += 25
        reasons.append("catalog coverage")
    if f["asn_class"] in ("cloud", "hosting"):
        s += 15
        reasons.append("datacenter address")
    return s, reasons
