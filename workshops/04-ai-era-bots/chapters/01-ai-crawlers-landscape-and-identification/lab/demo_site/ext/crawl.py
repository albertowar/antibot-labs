"""
W4 Ch1 extension: what the crawler layers need from the store that the gate does not give them.

  * robots.txt: your policy file (data/crawl_policy.robots) is appended to the base policy
    from DEFENSE_LEVEL 1 up (hooks.robots), so what you publish is what the check evaluates.
  * Request history. The Round 3 signature judges how a client *fetches*: does it load the
    stylesheet and images a browser would, how regular is its cadence, does it walk the
    sitemap in order. Static files and images are ungated, so they never get a Ctx and
    never reach a check. Two recorders fill the gap, both writing to Redis under lab:ch1:*
    (POST /lab/reset clears it):
        - an enricher records gated requests (pages, robots.txt, sitemap, feed), inside the
          gate, so a page the gate then refuses is still on the record;
        - a before_request registered after the gate records the ungated asset paths. It is
          after the gate on purpose: the gate never refuses an asset, and a before_request
          that ran first could not see the Ctx.
    Recording starts at DEFENSE_LEVEL 3, the first level that reads it.
  * A challenge type, "crawl_proof", that nobody can solve. The Round 4 policy may answer a
    suspected crawler with "challenge"; with no type registered the gate would enforce it
    as an anonymous block, and the scoreboard would not tell the two apart.
"""

import time

from flask import request

from defenses import crawl
from demo_site import hooks

_catalog = {}


def _robots_lines():
    from flask import current_app
    if current_app.config["LAB"].defense_level < 1:
        return []
    return crawl.policy_lines()


def _catalog_size():
    if "n" not in _catalog:
        from demo_site.models import Product
        _catalog["n"] = Product.query.filter_by(hidden=False, is_drop=False).count()
    return _catalog["n"]


def _record_gated(ctx):
    """Enricher: runs inside the gate before the checks, for every gated request."""
    if ctx.level < 3:
        return
    kind = crawl.kind_of(ctx.path)
    if kind == "other" or ctx.method not in ("GET", "HEAD"):
        return
    has_cookie = "sid" in ctx.cookies
    sku = crawl.sku_of(ctx.path)
    ctx.attrs["crawl_history"] = crawl.record(ctx.redis, ctx.ip, {
        "t": time.time(), "kind": kind, "path": ctx.path, "sku": sku, "cookie": has_cookie})
    if kind == "page":
        n = ctx.attrs["crawl_catalog"] = _catalog_size()
        if sku and not has_cookie:
            crawl.cluster_add(ctx.redis, ctx.ua.raw, ctx.edge.asn, sku)
        ctx.attrs["crawl_cluster"] = crawl.cluster_share(ctx.redis, ctx.ua.raw, ctx.edge.asn, n)


def init(app):
    hooks.robots(_robots_lines)
    hooks.enricher(_record_gated)
    hooks.challenges.register(
        crawl.CHALLENGE_TYPE,
        issue=lambda ctx: {"note": "No solver exists in this chapter: a challenge here reads as a stop."},
        verify=lambda ctx, answer: (False, "this challenge cannot be solved in W4 Ch1"))

    @app.before_request
    def _record_ungated():
        path = request.path
        if not path.startswith(("/static/", "/img/")) or app.config["LAB"].defense_level < 3:
            return None
        rds = app.extensions["lab_redis"]
        crawl.record(rds, request.remote_addr, {"t": time.time(), "kind": "asset", "path": path,
                                                "sku": None, "cookie": "sid" in request.cookies})
        return None
