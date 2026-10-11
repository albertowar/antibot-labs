"""W4 Ch1 demo store: the Workshop Store as an AI crawler sees it.

This is the Workshop 4 starter state of the shared store: an HTML catalog of 120
products with a sitemap, an RSS feed, static assets and a robots.txt, in front of
which this chapter builds crawler identification in four rounds:

    DEFENSE_LEVEL=1   defenses/crawler_registry.py   who claims to be a crawler, and what robots.txt says
    DEFENSE_LEVEL=2   defenses/crawler_verify.py     is the claim true (published ranges, FCrDNS)
    DEFENSE_LEVEL=3   defenses/crawl_signature.py    does an unclaimed client behave like a crawler
    DEFENSE_LEVEL=4   defenses/policy.py             identity x purpose -> allow / limit / challenge / block

Only HTML pages are gated (/, /products, /products/<sku>). robots.txt, the sitemap,
the feed, /health and static assets are always served: a crawler must be able to
read the policy you want it to follow. Each defense module is re-imported when its
file changes, so `checkpoint.py --round N --catch-up` takes effect without a restart.
Only DEFENSE_LEVEL needs a restart.

Lab-only plumbing (see lab_edge.py): X-Lab-Source-IP picks a source address from
data/world.json; X-Lab-Actor is ground truth for the scoreboard and is stripped
before any defense runs.
"""

from __future__ import annotations

import hashlib
import importlib
import json
import os
import sys
import time
from datetime import datetime, timezone

from flask import Flask, Response, g, jsonify, make_response, render_template_string, request
from markupsafe import escape

HERE = os.path.dirname(os.path.abspath(__file__))
LAB_DIR = os.path.dirname(HERE)
DATA_DIR = os.path.join(LAB_DIR, "data")
sys.path.insert(0, LAB_DIR)   # defenses/
sys.path.insert(0, HERE)      # store, lab_edge

from store import (  # noqa: E402
    ALLOW, BLOCK, CHALLENGE, LIMIT, BROWSER_LIKE, DECLARED_UNCHECKED, DECLARED_UNVERIFIABLE,
    DECLARED_UNLISTED, DECLARED_VERIFIED, IMPERSONATOR, UNDECLARED_CRAWLER,
    Decision_, Product, allow, block, db, log_decision, make_redis, seed_products,
)
from lab_edge import LabEdge  # noqa: E402
from defenses import netdb  # noqa: E402

DEFENSE_LEVEL = int(os.environ.get("DEFENSE_LEVEL", "0"))
ROBOTS_FILE = os.path.join(HERE, "robots.txt")
PER_PAGE = 20
HISTORY_WINDOW_S = 900
HISTORY_MAX = 400

app = Flask(__name__, static_folder=os.path.join(HERE, "static"), static_url_path="/static")
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get(
    "DATABASE_URL", f"sqlite:///{os.path.abspath(os.path.join(DATA_DIR, 'shop.db'))}")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db.init_app(app)
app.wsgi_app = LabEdge(app.wsgi_app, netdb.ALL_IPS, netdb.STUDENT_IP)
rds = make_redis()

# --- Defense modules, reloaded when their file changes ----------------------------
_mod_cache: dict[str, tuple[float, object]] = {}


def defense(name):
    path = os.path.join(LAB_DIR, "defenses", f"{name}.py")
    mtime = os.path.getmtime(path)
    cached = _mod_cache.get(name)
    if cached and cached[0] == mtime:
        return cached[1]
    mod = importlib.import_module(f"defenses.{name}")
    if cached:
        mod = importlib.reload(mod)
    _mod_cache[name] = (mtime, mod)
    return mod


def robots_text() -> str:
    with open(ROBOTS_FILE) as fh:
        return fh.read()


# --- Request plumbing --------------------------------------------------------------

def actor() -> str:
    return request.environ.get("lab.actor", "you")


def kind_of(path: str) -> str:
    if path.startswith("/static/"):
        return "asset"
    if path == "/robots.txt":
        return "robots"
    if path == "/sitemap.xml":
        return "sitemap"
    if path == "/feed.xml":
        return "feed"
    if path == "/health":
        return "health"
    if path.startswith("/lab/") or path.startswith("/admin/") or path == "/whoami":
        return "lab"
    return "page"


def sku_of(path: str) -> str | None:
    if path.startswith("/products/"):
        return path.split("/")[2] or None
    return None


def remember(ip: str, entry: dict) -> list[dict]:
    """Append to this address's request history and return the recent window."""
    key = f"hist:{ip}"
    rds.rpush(key, json.dumps(entry))
    rds.ltrim(key, -HISTORY_MAX, -1)
    rds.expire(key, HISTORY_WINDOW_S)
    cutoff = time.time() - HISTORY_WINDOW_S
    return [h for h in (json.loads(x) for x in rds.lrange(key, 0, -1)) if h["t"] >= cutoff]


def cluster_coverage(ua: str, asn: int, sku: str | None, has_cookie: bool) -> float:
    """Catalog share fetched by all cookie-less clients sharing (User-Agent, ASN).

    One scraper spread over many addresses still shares a client and a network.
    Clients that hold a session cookie are excluded: a thousand Chrome users on one
    ISP would otherwise look like one crawler. (Trade-off: a cookie-holding crawler
    is invisible to this signal. That is the Round 3 residual.)
    """
    if has_cookie:
        return 0.0
    key = f"clus:{hashlib.sha1(ua.encode()).hexdigest()[:10]}:{asn}"
    if sku:
        rds.sadd(key, sku)
        rds.expire(key, HISTORY_WINDOW_S)
    return rds.scard(key) / CATALOG_SIZE


def page_rate(ip: str) -> int:
    key = f"rate:{ip}:{int(time.time() // 60)}"
    n = rds.incr(key)
    rds.expire(key, 120)
    return int(n)


def default_action(level, identity, robots_ok, score, threshold):
    """What the store does before Round 4 wires a real policy.

    Blunt on purpose: every signal maps to allow or block. Round 4 replaces this with
    identity x purpose -> allow / limit / challenge / block.
    """
    if level >= 1 and identity != BROWSER_LIKE and not robots_ok:
        return block("robots.txt disallows this token here")
    if level >= 2 and identity == IMPERSONATOR:
        return block("claims a token from an address the operator does not publish")
    if level >= 3:
        if identity == UNDECLARED_CRAWLER:
            return block(f"undeclared crawler (score {score:.0f})")
        if identity in (DECLARED_UNVERIFIABLE, DECLARED_UNLISTED) and score >= threshold:
            return block(f"unverifiable crawler with crawler behaviour (score {score:.0f})")
    return allow("")


@app.before_request
def gate():
    path = request.path
    kind = kind_of(path)
    if kind == "lab":
        return None
    ip = request.remote_addr
    has_cookie = request.cookies.get("sid") is not None
    history = remember(ip, {"t": time.time(), "kind": kind, "path": path,
                            "sku": sku_of(path), "cookie": has_cookie})
    if kind != "page":
        return None

    t0 = time.perf_counter()
    ua = request.headers.get("User-Agent", "")
    net = netdb.info(ip)
    level = DEFENSE_LEVEL
    token, purpose, method, identity, robots_ok, score, reasons = "", "", "", BROWSER_LIKE, True, 0.0, []

    # L1: who does this client claim to be, and what does robots.txt say about it?
    ident = defense("crawler_registry").identify(ua) if level >= 1 else None
    if ident:
        token, purpose = ident["token"], ident["purpose"]
        identity = DECLARED_UNCHECKED if ident["listed"] else DECLARED_UNLISTED
        robots_ok = defense("crawler_registry").robots_allows(token, path, robots_text())
        # L2: is the claim true?
        if level >= 2 and ident["listed"]:
            status, method = defense("crawler_verify").verify(ip, token)
            identity = {"verified": DECLARED_VERIFIED, "impersonator": IMPERSONATOR,
                        "unverifiable": DECLARED_UNVERIFIABLE}[status]

    # L3: does an unverified client behave like a crawler?
    sig = defense("crawl_signature") if level >= 3 else None
    if sig and identity not in (DECLARED_VERIFIED, IMPERSONATOR):
        ccov = cluster_coverage(ua, net["asn"], sku_of(path), has_cookie)
        feats = sig.features(history, CATALOG_SIZE, ccov, net["asn_class"])
        score, reasons = sig.score(feats)
        if identity == BROWSER_LIKE and score >= sig.THRESHOLD:
            identity = UNDECLARED_CRAWLER
    threshold = sig.THRESHOLD if sig else 60

    # L4: the policy decides; before that, the blunt default mapping.
    decision = None
    if level >= 4:
        decision = defense("policy").decide(identity=identity, purpose=purpose, robots_ok=robots_ok,
                                            score=score, page_rate=page_rate(ip))
    if decision is None:
        decision = default_action(level, identity, robots_ok, score, threshold)

    lat = (time.perf_counter() - t0) * 1000
    log_decision(level=level, actor=actor(), client_ip=ip, asn_class=net["asn_class"], path=path[:120],
                 token=token[:48], identity=identity, purpose=purpose, verify_method=method, score=score,
                 action=decision.action,
                 reason=(decision.reason + (" | " + ", ".join(reasons) if reasons else ""))[:255],
                 latency_ms=lat)
    g.identity = identity
    if decision.action == ALLOW:
        return None
    if decision.action == LIMIT:
        return _refuse(429, "limit", decision)
    if decision.action == CHALLENGE:
        return _refuse(403, "challenge", decision)
    return _refuse(403, "block", decision)


def _refuse(status, outcome, decision):
    # A teaching lab tells the client why. A real endpoint never does.
    body = {"outcome": outcome, "reason": decision.reason}
    resp = jsonify(body)
    resp.status_code = status
    return resp


@app.after_request
def finish(resp):
    kind = kind_of(request.path)
    if kind != "lab":
        rds.rpush("accesslog", json.dumps({
            "ts": round(time.time(), 3), "actor": actor(), "ip": request.remote_addr,
            "asn_class": netdb.asn_class(request.remote_addr), "method": request.method,
            "path": request.path, "status": resp.status_code,
            "ua": request.headers.get("User-Agent", "")[:160],
            "cookie": request.cookies.get("sid") is not None}))
        rds.ltrim("accesslog", -5000, -1)
    if kind == "page" and resp.status_code == 200 and request.cookies.get("sid") is None:
        resp.set_cookie("sid", hashlib.sha1(f"{request.remote_addr}{time.time()}".encode()).hexdigest()[:16],
                        samesite="Lax")
    return resp


# --- The store ----------------------------------------------------------------------

LAYOUT = """<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>{{ title }} · Workshop Store</title>
<link rel="stylesheet" href="/static/store.css">
<link rel="alternate" type="application/rss+xml" title="New products" href="/feed.xml"></head>
<body>
<header>
  <a class="brand" href="/"><img src="/static/logo.svg" alt=""> Workshop Store</a>
  <nav><a href="/products?page=1">Catalog</a> <a href="/feed.xml">Feed</a></nav>
</header>
<main>{{ body|safe }}</main>
<footer><span>Defense level {{ level }}</span> &middot; <span id="js-ok">scripts did not run</span></footer>
<script src="/static/store.js"></script>
</body>
</html>"""


def page(title, body):
    return render_template_string(LAYOUT, title=title, body=body, level=DEFENSE_LEVEL)


def listing(page_no: int):
    total = CATALOG_SIZE
    pages = (total + PER_PAGE - 1) // PER_PAGE
    page_no = min(max(page_no, 1), pages)
    rows = Product.query.order_by(Product.sku).offset((page_no - 1) * PER_PAGE).limit(PER_PAGE).all()
    items = "".join(f'<li><a href="/products/{p.sku}">{escape(p.name)}</a> '
                    f'<span class="price">${p.price:.2f}</span></li>' for p in rows)
    nav = []
    if page_no > 1:
        nav.append(f'<a href="/products?page={page_no - 1}">&larr; previous</a>')
    if page_no < pages:
        nav.append(f'<a href="/products?page={page_no + 1}">next &rarr;</a>')
    body = (f'<h1>Catalog</h1><p>Page {page_no} of {pages}</p><ul class="catalog">{items}</ul>'
            f'<p class="pager">{" ".join(nav)}</p>')
    return page("Catalog", body)


@app.get("/")
def index():
    return listing(1)


@app.get("/products")
def products():
    try:
        n = int(request.args.get("page", "1"))
    except ValueError:
        n = 1
    return listing(n)


@app.get("/products/<sku>")
def product(sku):
    p = db.session.get(Product, sku)
    if not p:
        return page("Not found", "<h1>No such product</h1>"), 404
    related = (Product.query.filter(Product.category == p.category, Product.sku != p.sku)
               .order_by(Product.sku).limit(3).all())
    rel = " ".join(f'<a href="/products/{r.sku}">{escape(r.name)}</a>' for r in related)
    body = (f'<h1>{escape(p.name)}</h1><p class="price">${p.price:.2f}</p><p>{escape(p.blurb)}</p>'
            f'<p class="related">Related: {rel}</p>')
    return page(p.name, body)


@app.get("/robots.txt")
def robots():
    return Response(robots_text(), mimetype="text/plain")


@app.get("/sitemap.xml")
def sitemap():
    base = request.url_root.rstrip("/")
    urls = "".join(f"<url><loc>{base}/products/{p.sku}</loc></url>"
                   for p in Product.query.order_by(Product.sku).all())
    xml = f'<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">{urls}</urlset>'
    return Response(xml, mimetype="application/xml")


@app.get("/feed.xml")
def feed():
    base = request.url_root.rstrip("/")
    now = datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S GMT")
    items = "".join(f"<item><title>{escape(p.name)}</title><link>{base}/products/{p.sku}</link>"
                    f"<description>{escape(p.blurb)}</description></item>"
                    for p in Product.query.order_by(Product.sku.desc()).limit(10).all())
    xml = (f'<?xml version="1.0" encoding="UTF-8"?><rss version="2.0"><channel><title>Workshop Store</title>'
           f"<link>{base}/</link><description>New products</description><lastBuildDate>{now}</lastBuildDate>"
           f"{items}</channel></rss>")
    return Response(xml, mimetype="application/rss+xml")


@app.get("/health")
def health():
    return jsonify({"status": "ok", "level": DEFENSE_LEVEL})


# --- Lab instrumentation (not part of the product) -----------------------------------

@app.get("/whoami")
def whoami():
    ip = request.remote_addr
    return jsonify({"client_ip": ip, **netdb.info(ip), "ptr": netdb.ptr(ip), "actor": actor(),
                    "user_agent": request.headers.get("User-Agent", "")})


@app.get("/admin/status")
def status():
    return jsonify({"level": DEFENSE_LEVEL, "catalog_size": CATALOG_SIZE,
                    "decisions": Decision_.query.count()})


@app.get("/lab/decisions")
def lab_decisions():
    rows = Decision_.query.order_by(Decision_.ts).all()
    return jsonify([r.as_dict() for r in rows])


@app.get("/lab/log")
def lab_log():
    n = int(request.args.get("n", "200"))
    return jsonify([json.loads(x) for x in rds.lrange("accesslog", -n, -1)])


@app.post("/lab/reset")
def lab_reset():
    """Clear the decision log, the access log and all per-client state."""
    Decision_.query.delete()
    db.session.commit()
    rds.flushdb()
    return jsonify({"status": "ok"})


from sqlalchemy import event  # noqa: E402
from sqlalchemy.engine import Engine  # noqa: E402


@event.listens_for(Engine, "connect")
def _sqlite_pragmas(dbapi_conn, _record):
    if "sqlite3" in type(dbapi_conn).__module__:
        cur = dbapi_conn.cursor()
        cur.execute("PRAGMA journal_mode=WAL")
        cur.execute("PRAGMA synchronous=NORMAL")
        cur.close()


with app.app_context():
    db.create_all()
    seed_products()
    CATALOG_SIZE = Product.query.count()


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    print(f"W4 Ch1 Workshop Store on http://127.0.0.1:{port}  DEFENSE_LEVEL={DEFENSE_LEVEL}  "
          f"catalog={CATALOG_SIZE} products")
    app.run(host="127.0.0.1", port=port, threaded=True)
