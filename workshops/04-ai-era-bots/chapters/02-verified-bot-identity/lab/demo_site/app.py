"""W4 Ch2 demo store: a catalogue the crawlers want, with a crawler gate in front.

The store inherits the Workshop 3 shape (Flask + Redis, JSON catalogue, search) and
adds the one thing this chapter is about: a *gate* that decides, per request, who
the client is and which crawl budget it gets.

    anonymous lane   30 requests / minute / egress IP     (humans never notice)
    verified lane   600 requests / minute / identity      (the "good bot" fast lane)

A crawler that wants the fast lane has to be *verified* at the current
DEFENSE_LEVEL (see defenses/crawler_gate.py). Over budget means 429, never a
block: the lab keeps failed claimants in the anonymous lane so you can see what a
false negative and a false positive each cost. A detected *replay or forged
signature* (Round 4) is different and gets a 403.

Lab-only conventions, both honoured only from loopback:
    X-Lab-Egress   the IP the client "comes from" (RFC 5737 documentation ranges)
    X-Lab-Actor    ground truth for the scoreboard: bot-*, legit-human, legit-crawler-*

    DEFENSE_LEVEL=0 python demo_site/app.py          # PORT, MOCK_URL, REDIS_URL optional
"""

from __future__ import annotations

import ipaddress
import os
import sys
import time
from collections import deque

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
for _d in ("demo_site", "defenses"):
    sys.path.insert(0, os.path.join(ROOT, _d))

from flask import Flask, Response, g, jsonify, request  # noqa: E402

import crawler_gate  # noqa: E402
import resolver as resolver_mod  # noqa: E402
import store  # noqa: E402

LEVEL = int(os.environ.get("DEFENSE_LEVEL", "0"))
BUDGET = {"anonymous": 30, "verified": 600}       # requests per minute
UNGATED = ("/admin/", "/robots.txt", "/static/")

app = Flask(__name__)
r = store.connect()
resolver = resolver_mod.get_resolver()
decisions: deque = deque(maxlen=20000)

PRODUCTS = [{"id": i, "name": f"Lab Runner {i}", "price": 80 + (i * 7) % 90, "sku": f"LR-{i:04d}"}
            for i in range(1, 201)]


def _client_ip() -> str:
    """The egress IP of the client: the lab header from loopback, else the socket peer."""
    peer = request.remote_addr or "127.0.0.1"
    claimed = request.headers.get("X-Lab-Egress")
    if claimed and ipaddress.ip_address(peer).is_loopback:
        return claimed
    return peer


@app.before_request
def gate():
    if request.path.startswith(UNGATED):
        return None
    g.t0 = time.perf_counter()
    ctx = crawler_gate.RequestContext(
        ip=_client_ip(),
        method=request.method,
        authority=request.headers.get("Host", "").lower(),
        path=request.path,
        query=request.query_string.decode(),
        headers={k.lower(): v for k, v in request.headers.items()},
        actor=request.headers.get("X-Lab-Actor", "you"),
    )
    d = crawler_gate.decide(ctx, LEVEL, r, resolver)
    g.decision = d

    status, outcome = 200, "allow"
    if d.block:
        status, outcome = 403, "block"
    else:
        key = f"budget:{d.lane}:{d.identity if d.lane == 'verified' else ctx.ip}"
        n = r.incr(key)
        if n == 1:
            r.expire(key, 60)
        if n > BUDGET[d.lane]:
            status, outcome = 429, "budget"
    decisions.append({
        "ts": time.time(), "actor": ctx.actor, "ip": ctx.ip, "path": ctx.path,
        "claim": d.claim, "identity": d.identity, "method": d.method, "lane": d.lane,
        "outcome": outcome, "status": status, "reasons": d.reasons, "cost_ms": round(d.cost_ms, 3),
    })
    if status != 200:
        body = {"error": "crawl budget exceeded" if status == 429 else "request rejected",
                "lane": d.lane, "identity": d.identity, "reasons": d.reasons}
        return jsonify(body), status
    return None


@app.after_request
def timing(resp):
    d = getattr(g, "decision", None)
    if d is not None:
        resp.headers["Server-Timing"] = f"gate;dur={d.cost_ms:.3f}"
        resp.headers["X-Lane"] = d.lane
    return resp


@app.get("/")
def index():
    return Response("<h1>Lab Runner store</h1><p>200 products. <a href='/api/products'>/api/products</a>, "
                    "<a href='/robots.txt'>/robots.txt</a>, <a href='/admin/status'>/admin/status</a></p>",
                    mimetype="text/html")


@app.get("/robots.txt")
def robots():
    # Always served, never gated: a crawler that can't read robots.txt can't obey it.
    return Response("User-agent: *\nDisallow: /admin/\nDisallow: /api/search\n", mimetype="text/plain")


@app.get("/api/products")
def products():
    page = max(1, int(request.args.get("page", 1)))
    per = min(50, max(1, int(request.args.get("per_page", 20))))
    items = PRODUCTS[(page - 1) * per: page * per]
    return jsonify({"page": page, "per_page": per, "total": len(PRODUCTS), "items": items})


@app.get("/product/<int:pid>")
def product(pid):
    item = next((p for p in PRODUCTS if p["id"] == pid), None)
    return (jsonify(item), 200) if item else (jsonify({"error": "no such product"}), 404)


@app.get("/api/search")
def search():
    q = request.args.get("q", "").lower()
    return jsonify([p for p in PRODUCTS if q in p["name"].lower()][:20])


@app.get("/admin/status")
def status():
    return jsonify({"level": LEVEL, "budgets": BUDGET, "mock_url": resolver_mod.MOCK_URL,
                    "decisions": len(decisions)})


@app.get("/admin/decisions")
def admin_decisions():
    limit = int(request.args.get("limit", 2000))
    rows = list(decisions)
    return jsonify(rows[-limit:])


@app.post("/admin/reset")
def reset():
    """?scope=budgets clears only the per-minute counters; the default clears caches and the log too."""
    if request.args.get("scope") == "budgets":
        n = 0
        patterns = ["budget:*"] + (["rdns:*"] if request.args.get("cache") == "rdns" else [])
        for pat in patterns:
            for key in r.scan_iter(pat):
                r.delete(key)
                n += 1
        return jsonify({"ok": True, "budgets_cleared": n})
    r.flushdb()
    decisions.clear()
    return jsonify({"ok": True})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    print(f"demo store on http://127.0.0.1:{port}  (DEFENSE_LEVEL={LEVEL}, "
          f"store={'memory' if os.environ.get('REDIS_URL', 'memory://').startswith('memory') else 'redis'}, "
          f"mock internet at {resolver_mod.MOCK_URL})")
    app.run(host="127.0.0.1", port=port)
