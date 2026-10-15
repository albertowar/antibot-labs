"""W4 Ch3 extension: the published policy, the maze and the paywall, on the Kestrel store.

The gate's verdict set is closed (allow, monitor, challenge, block, rate_limit, deceive), and a
decoy page, a 402 and a "charged" 200 are not in it. So the defenses (defenses/maze.py,
defenses/paywall.py) are ordinary checks that record what they decided in `ctx.attrs`, and this
module, whose `before_request` is registered AFTER the gate's, enacts it:

    ctx.attrs["maze"]     -> a decoy page, 200, g.outcome = "mazed"
    paywall.action ==
      "paywall"           -> 402 Payment Required + `crawler-price: USD 0.01`, g.outcome = "paywalled"
      "charged"           -> the page is served, `crawler-charged: USD 0.01` is stamped on it, the
                             ledger (Redis, lab:ledger:*) is credited, g.outcome = "charged"

Because the gate's own answer (a 403 from `enforce`) comes first, a request the gate refused never
reaches this module. The scoreboard (contract 1.6) gives each custom outcome its own column, next
to `blocked`, so a round can report "paywalled 120, charged 120" beside "shoppers hurt 0".

What else this adds to the store, all of it ext-only:

  Routes    GET /llms.txt (a map for agents, not a control)           every level
            GET /license.xml                                          RSL 1.0 licence; level >= 1
            GET /.well-known/tdmrep.json, /.well-known/tdm-policy.json
                                                                      W3C TDMRep; level >= 1
            GET /api/products.json                                    the whole catalogue in one JSON
                                                                      document (a bulk feed; a leak
                                                                      carrier unless it is priced)
            GET /maze/<token>                                         decoy pages; level >= 3
            GET /lab/crawl/stats                                      ledger and maze counters (ungated)
  Headers   `Content-Usage` + `Link: rel="license"` from defenses/crawl_policy.py and the TDMRep
            `tdm-reservation` / `tdm-policy` pair, on every gated response at level >= 1
  Robots    the policy's lines, appended to the base robots.txt with hooks.robots()
  Page      a hidden entry link into the maze at the end of every page (body_end slot), level >= 3

Everything the maze and the ledger keep is in Redis under `lab:` so POST /lab/reset forgets it.
The enact step's time counts as defender cost (g.gate_ms), like the checks'.
"""

import hashlib
import html
import importlib
import json
import threading
import time

from flask import Blueprint, Response, current_app, g, jsonify, request
from markupsafe import Markup

from .. import hooks
from ..models import Product

bp = Blueprint("deterrence", __name__)
_babbler = None
_inflight = None


def _d(name):
    """A defense module, looked up at call time (the reloader reloads in place; a held reference would go stale)."""
    return importlib.import_module(f"defenses.{name}")


def _base():
    return request.host_url.rstrip("/")


def _level():
    return current_app.config["LAB"].defense_level


def _redis():
    return current_app.extensions["lab_redis"]


# --- the published policy ----------------------------------------------------------------------

def _robots_lines():
    if _level() < 1:
        return []
    policy = _d("crawl_policy")
    return policy.robots_lines(_base(), policy.effective_rules(_level()))


@bp.route("/llms.txt")
def llms_txt():
    # A map for agents, not a control: it tells a reader where things are and expresses no
    # permission at all. Served at every level to make that point.
    return Response("# Kestrel Outfitters\n\n> A small outdoor-gear shop used in the Antibot Workshop.\n\n"
                    "## Catalogue\n- [Listing](/products): 24 products per page\n"
                    "- [JSON API](/api/products): the same, as JSON\n- [Bulk feed](/api/products.json)\n\n"
                    "## Policy\n- [robots.txt](/robots.txt)\n- [RSL licence](/license.xml)\n",
                    mimetype="text/markdown")


@bp.route("/license.xml")
def license_xml():
    if _level() < 1:
        return Response("404\n", 404, mimetype="text/plain")
    policy, paywall = _d("crawl_policy"), _d("paywall")
    price = float(paywall.PAYWALL["price_usd"]) if _level() >= 4 else 0.0
    return Response(policy.rsl_xml(_base(), policy.effective_rules(_level()), price), mimetype="application/rsl+xml")


@bp.route("/.well-known/tdmrep.json")
def tdmrep():
    if _level() < 1:
        return Response("404\n", 404, mimetype="text/plain")
    return jsonify([{"location": "/*", "tdm-reservation": 1, "tdm-policy": f"{_base()}/.well-known/tdm-policy.json"}])


@bp.route("/.well-known/tdm-policy.json")
def tdm_policy():
    if _level() < 1:
        return Response("404\n", 404, mimetype="text/plain")
    return Response(json.dumps({
        "@context": {"odrl": "http://www.w3.org/ns/odrl/2/", "tdm": "https://www.w3.org/ns/tdmrep#"},
        "@type": "odrl:Policy", "uid": f"{_base()}/.well-known/tdm-policy.json",
        "odrl:permission": [{"odrl:action": "tdm:mine", "odrl:constraint": "licence required: see /license.xml"}]}),
        mimetype="application/json")


@bp.route("/api/products.json")
def products_bulk():
    rows = Product.query.filter_by(hidden=False, is_drop=False).order_by(Product.id).all()
    return jsonify(total=len(rows), items=[p.to_dict() for p in rows])


# --- the maze ----------------------------------------------------------------------------------

def _babble():
    global _babbler
    if _babbler is None:
        from defenses.babble import Babbler
        _babbler = Babbler([p.blurb for p in Product.query.all()])
    return _babbler


def _entry():
    """The hidden entry link (Jinja global, rendered in the body_end slot of every page)."""
    ctx = getattr(g, "ctx", None)
    if ctx is None or ctx.level < 3:
        return ""
    return Markup(_d("maze").entry_link(ctx.ip, _d("maze").SECRET))


def _maze_response(ctx, token=None):
    """A decoy page for `ctx`: deterministic, noindex, dripped inside a concurrency cap."""
    mz, r = _d("maze"), _redis()
    token = token or hashlib.sha256(f"{mz.SECRET}:dark:{ctx.ip}".encode()).hexdigest()[:12]
    t0 = time.perf_counter()
    title, paragraphs, children = mz.render(token, _babble(), mz.SECRET)
    links = "".join(f"<li><a href='{mz.MAZE_PREFIX}{c}'>{html.escape(title.split()[0])} {i}</a></li>"
                    for i, c in enumerate(children))
    doc = (f"<!doctype html><html><head><meta charset='utf-8'><title>{html.escape(title)}</title>"
           f"<meta name='robots' content='noindex, nofollow'></head><body><h1>{html.escape(title)}</h1>"
           + "".join(f"<p>{html.escape(x)}</p>" for x in paragraphs) + f"<ul>{links}</ul></body></html>")
    r.incrbyfloat("lab:maze:gen_ms", (time.perf_counter() - t0) * 1000)
    r.incrby("lab:maze:bytes", len(doc))
    r.incr("lab:maze:pages")
    g.outcome = "mazed"
    headers = {"X-Robots-Tag": "noindex, nofollow", "Cache-Control": "no-store"}
    if not _inflight.acquire(blocking=False):
        r.incr("lab:maze:capped")
        return Response(doc, 200, headers, mimetype="text/html")

    def drip():
        try:
            step = max(1, len(doc) // mz.DRIP_CHUNKS)
            for i in range(0, len(doc), step):
                yield doc[i:i + step]
                time.sleep(mz.DRIP_DELAY)
        finally:
            _inflight.release()
    return Response(drip(), 200, headers, mimetype="text/html")


@bp.route("/maze/<token>")
def maze_page(token):
    ctx = g.ctx
    if ctx.level < 3 or len(token) != 12 or not all(c in "0123456789abcdef" for c in token):
        return Response("404\n", 404, mimetype="text/plain")
    ctx.note(maze_hit=_d("maze").record_hit(ctx.redis, ctx.ip))
    return _maze_response(ctx, token)


@bp.route("/lab/crawl/stats")
def crawl_stats():
    r = _redis()
    ledger = {k.split(":", 2)[2]: round(float(r.get(k) or 0), 4) for k in r.scan_iter("lab:ledger:*")}
    return jsonify(ledger=ledger, maze={
        "pages": int(r.get("lab:maze:pages") or 0), "gen_ms_total": float(r.get("lab:maze:gen_ms") or 0),
        "bytes": int(r.get("lab:maze:bytes") or 0), "capped": int(r.get("lab:maze:capped") or 0)})


# --- enacting the checks' answers --------------------------------------------------------------

def _enact():
    """before_request, registered after the gate's: answer what the maze and paywall checks decided."""
    ctx = getattr(g, "ctx", None)
    if ctx is None or not (ctx.attrs.get("maze") or ctx.attrs.get("paywall")):
        return None
    t0 = time.perf_counter()
    try:
        if ctx.attrs.get("maze") and not request.path.startswith("/maze/"):
            return _maze_response(ctx)
        offer = ctx.attrs.get("paywall")
        if offer is not None and offer.action == "paywall":
            g.outcome = "paywalled"
            return Response("402 Payment Required\n", 402, {"crawler-price": f"USD {offer.price:.2f}"},
                            mimetype="text/plain")
        if offer is not None and offer.action == "charged":
            g.charged = (ctx.attrs["identity"].operator, offer.price)       # the ledger waits for a 200
            g.outcome = "charged"
        return None
    finally:
        g.gate_ms = getattr(g, "gate_ms", 0.0) + (time.perf_counter() - t0) * 1000


def _stamp(response):
    ctx = getattr(g, "ctx", None)
    if ctx is None:
        return response
    if getattr(g, "charged", None):
        operator, price = g.charged
        if response.status_code == 200:
            response.headers["crawler-charged"] = f"USD {price:.2f}"
            _redis().incrbyfloat(f"lab:ledger:{operator}", price)
            _redis().incrbyfloat("lab:ledger:total", price)
        else:
            g.outcome = None                    # nothing was delivered, nothing is billed
    if ctx.level >= 1:
        policy = _d("crawl_policy")
        for k, v in policy.response_headers(_base(), request.path, policy.effective_rules(ctx.level)).items():
            response.headers[k] = v
        response.headers["tdm-reservation"] = "1"
        response.headers["tdm-policy"] = f"{_base()}/.well-known/tdm-policy.json"
    return response


def init(app):
    global _inflight
    _inflight = threading.BoundedSemaphore(_d("maze").MAX_INFLIGHT)
    app.jinja_env.globals["crawl_entry"] = _entry
    hooks.slot("body_end", "crawl/entry.html")
    hooks.robots(_robots_lines)
    app.register_blueprint(bp)
    app.before_request(_enact)                  # after the gate's before_request: it only sees what the gate allowed
    app.after_request(_stamp)                   # runs before the gate's stamp, which reads g.outcome
