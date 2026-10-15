"""Round 3: does an unclaimed client behave like a crawler?

The stealth crawler claims nobody: a browser User-Agent from a rented cloud address.
Registry and verification have nothing to say. What it cannot hide is how it fetches.

features() is given. It turns one address's recent request history (plus one
collective signal) into numbers:

  n_requests, n_pages, n_assets   evidence so far (non-asset requests, pages, assets)
  asset_ratio        assets per page: browsers load the stylesheet, script and images, parsers 0
  cadence_cv         coefficient of variation of gaps between pages: loops ~0, people ~1
  sitemap_order      share of consecutive product fetches in ascending SKU order
  cookie_continuity  share of pages sent with our session cookie
  coverage           distinct products fetched by this address / catalog size
  asn_type           residential / mobile / corporate / datacenter (defenses/netinfo.py: VPNs,
                     privacy relays, cloud and hosting ranges all read "datacenter")
  cluster_cov        catalog share fetched by ALL cookie-less clients sharing this
                     client's (User-Agent, ASN) pair, i.e. one crawler on many addresses
  robots_fetched     whether this address ever asked for /robots.txt

The history is recorded by demo_site/ext/crawl.py, because static files and images never
reach the gate: the store only learns that a client "loaded the page like a browser" if
something watches the paths the gate skips.

score(features) is yours: return (points, reasons). The check labels a browser-like
client "undeclared-crawler" at or above THRESHOLD. Two rules to keep:

  * Do not judge on thin evidence. Below MIN_EVIDENCE requests an address is not a
    crawler, it is a link preview, an uptime check or someone with curl. Scrapers
    must make many requests; previewers never do.
  * Collective signals may fire earlier than individual ones: a cluster that has
    already fetched a third of the catalog is a crawler whatever this address did.

This is the reference solution; the residual it leaves is the chapter's point. A polite crawler
spread over residential-looking addresses that keeps a session cookie scores like a crowd of
shoppers: at the HTTP level that is the end of the road. W4 Ch2 makes the good ones prove who
they are and W4 Ch3 makes the rest pay for every page.

Check the cost in tools/checkpoint.py: the shoppers (including the ones on VPN and privacy-relay
addresses), the RSS reader, the link unfurler, the uptime monitor and the developer with curl
must all stay at 0 blocked.
"""

from __future__ import annotations

import statistics

from . import crawl, netinfo
from .pipeline import Check

MIN_EVIDENCE = 4        # non-asset requests from one address before we judge it
THRESHOLD = 60          # score at or above this = undeclared crawler
CLUSTER_TRIP = 0.35     # catalog share a cookie-less (UA, ASN) cluster may fetch


def features(history: list[dict], catalog_size: int, cluster_cov: float, asn_type: str) -> dict:
    pages = [h for h in history if h["kind"] == "page"]
    assets = [h for h in history if h["kind"] == "asset"]
    n_pages = len(pages)
    f = {"n_requests": sum(1 for h in history if h["kind"] != "asset"), "n_pages": n_pages,
         "n_assets": len(assets), "asn_type": asn_type, "cluster_cov": cluster_cov,
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
    if f["asn_type"] == "datacenter":
        s += 15
        reasons.append("datacenter address")
    return s, reasons


def _check(ctx):
    """Given: score every client that is neither verified nor a proven impersonator."""
    if not crawl.is_page(ctx):
        return None
    st = crawl.state(ctx)
    if st["identity"] not in (crawl.DECLARED_VERIFIED, crawl.IMPERSONATOR):
        feats = features(ctx.attrs.get("crawl_history", []), ctx.attrs.get("crawl_catalog", 0),
                         ctx.attrs.get("crawl_cluster", 0.0), netinfo.lookup(ctx.ip)["asn_type"])
        st["score"], st["reasons"] = score(feats)
        if st["identity"] == crawl.BROWSER_LIKE and st["score"] >= THRESHOLD:
            st["identity"] = crawl.UNDECLARED_CRAWLER
    return crawl.enforce(ctx, THRESHOLD)


CHECK = Check("crawl_signature", _check)
