"""W4 Ch3 demo store — one catalogue, four rungs of crawler governance.

The shop every AI crawler in this chapter wants: 300 products served the way a
real shop serves them, through HTML, search, a JSON API and a sitemap.

    /                      home                      /catalog?page=N   listing (20/page)
    /product/<sku>         product page              /search?q=        up to 50 matches
    /api/products.json     JSON listing (20/page)    /sitemap.xml      every product URL
    /robots.txt /license.xml /llms.txt               the published policy (Round 1)
    /maze/<token>          decoy pages (Round 3)

DEFENSE_LEVEL selects how far up the ladder the store is (cumulative):

    0  nothing: every request served
    1  policy published (defenses/crawl_policy.py); robots.txt violations logged
    2  policy enforced on verifiable crawlers (defenses/enforce.py)
    3  hidden maze for everyone else (defenses/maze.py)
    4  402 pay-per-crawl for licensed purposes (defenses/paywall.py)

The identity verdict (defenses/bot_identity.py) and the known-crawler registry
are given infrastructure from W4 Ch1-2. Each round's defense module is imported
fresh on every request, so `checkpoint.py --round N --catch-up` takes effect
without a restart; changing DEFENSE_LEVEL does need a restart.

Lab-only shortcuts, all loopback-only:
  * X-Lab-Client-IP  — the source IP a real CDN would hand us (RFC 5737 ranges).
  * X-Lab-Actor      — ground truth (human / prefetch / reader / search / bot) for
                       the scoreboard only.
A real endpoint has none of these oracles; they exist to measure both sides.
"""

from __future__ import annotations

import hashlib
import html
import importlib
import ipaddress
import os
import sys
import threading
import time

from flask import Flask, Response, g, jsonify, request

HERE = os.path.dirname(os.path.abspath(__file__))
LAB_DIR = os.path.dirname(HERE)
DATA_DIR = os.path.join(LAB_DIR, "data")
sys.path.insert(0, LAB_DIR)       # for defenses/
sys.path.insert(0, HERE)          # for store

from store import (  # noqa: E402
    ALLOW, BLOCK, CHARGED, MAZE, PAYWALL,
    Decision_, Product, allow, block, db, log_decision, make_redis,
)
from defenses import bot_identity, crawler_registry  # noqa: E402
from defenses.babble import Babbler  # noqa: E402

LEVEL = int(os.environ.get("DEFENSE_LEVEL", "0"))
SECRET = os.environ.get("LAB_SECRET_KEY", "w4ch3-lab-fixed-secret-not-for-prod")
PAGE = 20

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get(
    "DATABASE_URL", f"sqlite:///{os.path.abspath(os.path.join(DATA_DIR, 'shop.db'))}"
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db.init_app(app)

rds = make_redis()
_babbler = None
_inflight = threading.BoundedSemaphore(8)


def defense(name):
    """Import a round's defense fresh, so --catch-up edits take effect live."""
    return importlib.reload(importlib.import_module(f"defenses.{name}"))


def babbler():
    global _babbler
    if _babbler is None:
        _babbler = Babbler([p.description for p in Product.query.all()])
    return _babbler


# --- request context ------------------------------------------------------------

def _loopback(addr: str) -> bool:
    try:
        return ipaddress.ip_address(addr).is_loopback
    except ValueError:
        return False


def client_ip() -> str:
    if _loopback(request.remote_addr or ""):
        fwd = request.headers.get("X-Lab-Client-IP")
        if fwd:
            return fwd.strip()
    return request.remote_addr or "0.0.0.0"


def actor() -> str:
    return request.headers.get("X-Lab-Actor", "unknown")


def base_url() -> str:
    return request.host_url.rstrip("/")


def effective_rules():
    """purpose -> allow | deny | licensed. Round 4's paywall flips the licensed purposes."""
    rules = {"search": "allow", "ai-train": "deny", "ai-input": "deny"}
    if LEVEL >= 4:
        pw = defense("paywall").PAYWALL
        if pw["enabled"]:
            for p in pw["purposes"]:
                rules[p] = "licensed"
    return rules


def price_usd() -> float:
    return float(defense("paywall").PAYWALL["price_usd"]) if LEVEL >= 4 else 0.0


# --- the gate every content route passes through --------------------------------

def gate(path: str, skus: list[str]):
    """Run the ladder for this request. Returns (Decision, Identity)."""
    t0 = time.perf_counter()
    ip = client_ip()
    ident = bot_identity.verify(request.headers, ip, request.host)
    rules = effective_rules()
    rule = rules.get(ident.purpose) if ident.operator else None
    policy = defense("crawl_policy")
    disallowed = policy.is_disallowed(rule, path)
    vkey = f"violations:{ip}:{ident.operator or '-'}"
    violations = int(rds.get(vkey) or 0)

    decision = allow("served")
    if LEVEL >= 3 and defense("maze").tagged(rds, ip):
        decision = _maze_decision(ip)
    elif LEVEL >= 2:
        decision = defense("enforce").evaluate({
            "identity": ident, "ua_class": crawler_registry.classify_ua(request.user_agent.string),
            "path": path, "rule": rule, "disallowed": disallowed, "violations": violations,
        })
    if decision.action == ALLOW and LEVEL >= 4 and rule == "licensed":
        pw = defense("paywall")
        if pw.applies(path):
            decision = pw.evaluate({
                "identity": ident, "path": path, "price": price_usd(),
                "exact": request.headers.get("crawler-exact-price"),
                "max": request.headers.get("crawler-max-price"),
            })
    if LEVEL >= 1 and disallowed and decision.action in (ALLOW, CHARGED):
        # Served, but the client ignored robots.txt: the Round 1 "violations" log.
        rds.incr(vkey)
        rds.expire(vkey, 3600)
        decision = decision._replace(reason=f"robots-violation #{violations + 1}: {decision.reason}")
    if decision.action == CHARGED:
        rds.incrbyfloat(f"ledger:{ident.operator}", decision.charged)
        rds.incrbyfloat("ledger:total", decision.charged)
    g.lat_ms = (time.perf_counter() - t0) * 1000
    log_decision(
        level=LEVEL, actor=actor(), path=path[:255], client_ip=ip,
        ua_class=crawler_registry.classify_ua(request.user_agent.string),
        operator=ident.operator, verified=bool(ident.verified), outcome=decision.action,
        reason=decision.reason[:255], charged=decision.charged,
        skus=",".join(skus) if decision.action in (ALLOW, CHARGED) else "",
        latency_ms=g.lat_ms,
    )
    return decision, ident


def _maze_decision(ip):
    from store import Decision
    return Decision(MAZE, 90.0, f"{ip} is maze-tagged: catalogue dark, decoy served", 0.0)


def finish(decision, body_fn, path, is_html=True):
    """Turn a Decision into the HTTP response, with the Round 1 headers on content."""
    hdrs = {"Server-Timing": f"gate;dur={g.lat_ms:.2f}"}
    if LEVEL >= 1:
        hdrs.update(defense("crawl_policy").response_headers(base_url(), path, effective_rules()))
    if decision.action == BLOCK:
        return Response(f"403 Forbidden\n{decision.reason}\n", 403, hdrs, mimetype="text/plain")
    if decision.action == PAYWALL:
        hdrs["crawler-price"] = f"USD {decision.charged:.2f}"
        return Response("402 Payment Required\n", 402, hdrs, mimetype="text/plain")
    if decision.action == MAZE:
        return maze_response(client_ip(), token=None, headers=hdrs)
    if decision.action == CHARGED:
        hdrs["crawler-charged"] = f"USD {decision.charged:.2f}"
    body, mimetype = body_fn()
    return Response(body, 200, hdrs, mimetype=mimetype)


# --- HTML -------------------------------------------------------------------------

CSS = "body{font-family:sans-serif;max-width:52rem;margin:2rem auto}.hp{display:none}"


def page(title, body_html, extra_head=""):
    entry = defense("maze").entry_link({"client_ip": client_ip()}, SECRET) if LEVEL >= 3 else ""
    return (f"<!doctype html><html><head><meta charset='utf-8'><title>{html.escape(title)}</title>"
            f"<style>{CSS}</style>{extra_head}</head><body>{entry}"
            f"<nav><a href='/'>Lab Store</a> · <a href='/catalog?page=1'>Catalogue</a> · "
            f"<form action='/search' style='display:inline'><input name='q' placeholder='search'></form></nav>"
            f"<h1>{html.escape(title)}</h1>{body_html}</body></html>")


def product_li(p):
    return (f"<li><a href='/product/{p.sku}' data-sku='{p.sku}'>{html.escape(p.name)}</a> "
            f"— ${p.price:.2f}</li>")


@app.get("/")
def home():
    d, _ = gate("/", [])
    return finish(d, lambda: (page("Lab Store", "<p>300 products. <a href='/catalog?page=1'>Browse the catalogue</a>.</p>"), "text/html"), "/")


@app.get("/catalog")
def catalog():
    n = max(1, int(request.args.get("page", 1)))
    prods = Product.query.order_by(Product.sku).offset((n - 1) * PAGE).limit(PAGE).all()
    path = f"/catalog?page={n}"
    d, _ = gate(path, [p.sku for p in prods])

    def body():
        items = "".join(product_li(p) for p in prods)
        nav = f"<p><a href='/catalog?page={n + 1}'>Next page</a></p>" if len(prods) == PAGE else ""
        return page(f"Catalogue, page {n}", f"<ul>{items}</ul>{nav}"), "text/html"
    return finish(d, body, path)


@app.get("/product/<sku>")
def product(sku):
    p = Product.query.get(sku)
    if not p:
        return Response("404\n", 404, mimetype="text/plain")
    path = f"/product/{sku}"
    d, _ = gate(path, [sku])
    return finish(d, lambda: (page(p.name, f"<p><b>${p.price:.2f}</b> · {html.escape(p.category)}</p>"
                                           f"<p>{html.escape(p.description)}</p>"), "text/html"), path)


@app.get("/search")
def search():
    q = (request.args.get("q") or "").strip().lower()
    prods = (Product.query.filter(Product.name.ilike(f"%{q}%")).order_by(Product.sku).limit(50).all()
             if q else [])
    path = f"/search?q={q}"
    d, _ = gate(path, [p.sku for p in prods])
    return finish(d, lambda: (page(f"Search: {q}", "<ul>" + "".join(product_li(p) for p in prods) + "</ul>"),
                              "text/html"), path)


@app.get("/api/products.json")
def api_products():
    n = max(1, int(request.args.get("page", 1)))
    prods = Product.query.order_by(Product.sku).offset((n - 1) * PAGE).limit(PAGE).all()
    path = f"/api/products.json?page={n}"
    d, _ = gate(path, [p.sku for p in prods])
    import json
    return finish(d, lambda: (json.dumps({"page": n, "products": [
        {"sku": p.sku, "name": p.name, "price": p.price, "category": p.category} for p in prods]}),
        "application/json"), path)


@app.get("/sitemap.xml")
def sitemap():
    skus = [p.sku for p in Product.query.order_by(Product.sku).all()]
    d, _ = gate("/sitemap.xml", [])
    urls = "".join(f"<url><loc>{base_url()}/product/{s}</loc></url>" for s in skus)
    return finish(d, lambda: (f'<?xml version="1.0" encoding="UTF-8"?>'
                              f'<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">{urls}</urlset>',
                              "application/xml"), "/sitemap.xml")


# --- the published policy (Round 1) ----------------------------------------------

@app.get("/robots.txt")
def robots():
    if LEVEL < 1:
        return Response("User-agent: *\nAllow: /\n", mimetype="text/plain")
    return Response(defense("crawl_policy").robots_txt(base_url(), effective_rules()), mimetype="text/plain")


@app.get("/license.xml")
def license_xml():
    if LEVEL < 1:
        return Response("404\n", 404, mimetype="text/plain")
    return Response(defense("crawl_policy").rsl_xml(base_url(), effective_rules(), price_usd()),
                    mimetype="application/rsl+xml")


@app.get("/llms.txt")
def llms_txt():
    # A map for agents, not a control: it tells a reader where things are and
    # expresses no permission at all. Served at every level to make that point.
    return Response("# Lab Store\n\n> A 300-product demo shop used in the Antibot Workshop.\n\n"
                    "## Catalogue\n- [Listing](/catalog?page=1): 20 products per page\n"
                    "- [JSON API](/api/products.json?page=1)\n\n## Policy\n- [robots.txt](/robots.txt)\n"
                    "- [RSL licence](/license.xml)\n", mimetype="text/markdown")


# --- the maze (Round 3) ------------------------------------------------------------

def maze_response(ip, token=None, headers=None):
    mz = defense("maze")
    # A tagged client asking for the catalogue gets a decoy page keyed on its IP.
    token = token or hashlib.sha256(f"{SECRET}:dark:{ip}".encode()).hexdigest()[:12]
    t0 = time.perf_counter()
    title, paragraphs, children = mz.render(token, babbler(), SECRET)
    gen_ms = (time.perf_counter() - t0) * 1000
    rds.incrbyfloat("maze:gen_ms", gen_ms)
    links = "".join(f"<li><a href='{mz.MAZE_PREFIX}{c}'>{html.escape(title.split()[0])} {i}</a></li>"
                    for i, c in enumerate(children))
    doc = page(title, "".join(f"<p>{html.escape(x)}</p>" for x in paragraphs) + f"<ul>{links}</ul>",
               extra_head="<meta name='robots' content='noindex, nofollow'>")
    rds.incrby("maze:bytes", len(doc))
    hdrs = dict(headers or {})
    hdrs["X-Robots-Tag"] = "noindex, nofollow"
    hdrs["Cache-Control"] = "no-store"
    slow = _inflight.acquire(blocking=False)
    if not slow:
        rds.incr("maze:capped")
        return Response(doc, 200, hdrs, mimetype="text/html")

    def drip():
        try:
            step = max(1, len(doc) // mz.DRIP_CHUNKS)
            for i in range(0, len(doc), step):
                yield doc[i:i + step]
                time.sleep(mz.DRIP_DELAY)
        except BaseException as exc:  # noqa: BLE001  (lab diagnostics)
            print(f"[maze drip] {type(exc).__name__}: {exc}", flush=True)
            raise
        finally:
            _inflight.release()
    return Response(drip(), 200, hdrs, mimetype="text/html")


@app.get("/maze/<token>")
def maze(token):
    if LEVEL < 3 or not all(c in "0123456789abcdef" for c in token) or len(token) != 12:
        return Response("404\n", 404, mimetype="text/plain")
    ip = client_ip()
    mz = defense("maze")
    n = mz.record_hit(rds, ip)
    g.lat_ms = 0.0
    log_decision(level=LEVEL, actor=actor(), path=f"/maze/{token}", client_ip=ip,
                 ua_class=crawler_registry.classify_ua(request.user_agent.string),
                 operator="", verified=False, outcome=MAZE,
                 reason=f"maze page #{n} for this IP", charged=0.0, skus="", latency_ms=0.0)
    return maze_response(ip, token=token)


# --- lab oracle (never ship) ------------------------------------------------------

@app.get("/whoami")
def whoami():
    ident = bot_identity.verify(request.headers, client_ip(), request.host)
    return jsonify({"level": LEVEL, "client_ip": client_ip(),
                    "ua_class": crawler_registry.classify_ua(request.user_agent.string),
                    "identity": ident._asdict(), "rules": effective_rules()})


@app.post("/lab/reset")
def lab_reset():
    Decision_.query.delete()
    db.session.commit()
    rds.flushdb()
    return jsonify({"ok": True})


@app.get("/lab/decisions")
def lab_decisions():
    q = Decision_.query
    if request.args.get("level"):
        q = q.filter_by(level=int(request.args["level"]))
    cols = ("ts", "level", "actor", "path", "client_ip", "ua_class", "operator", "verified",
            "outcome", "reason", "charged", "skus", "latency_ms")
    return jsonify([{c: getattr(r, c) for c in cols} for r in q.order_by(Decision_.id).all()])


@app.get("/lab/stats")
def lab_stats():
    ledger = {k.split(":", 1)[1]: float(v) for k, v in
              ((k, rds.get(k)) for k in rds.keys("ledger:*"))}
    maze_pages = sum(int(v) for v in (rds.get(k) for k in rds.keys("maze:hits:*")) if v)
    return jsonify({"ledger": ledger, "maze": {
        "pages": maze_pages, "gen_ms_total": float(rds.get("maze:gen_ms") or 0),
        "bytes": int(rds.get("maze:bytes") or 0), "capped": int(rds.get("maze:capped") or 0)}})


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        if Product.query.count() == 0:
            raise SystemExit("Empty catalogue: run `python tools/seed.py` first.")
    port = int(os.environ.get("PORT", "5000"))
    print(f"W4 Ch3 store on http://127.0.0.1:{port}  DEFENSE_LEVEL={LEVEL}")
    app.run(host="127.0.0.1", port=port, threaded=True)
