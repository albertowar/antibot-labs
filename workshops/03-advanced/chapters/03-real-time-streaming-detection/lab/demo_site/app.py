"""
W3 Ch3 — Demo store with a live streaming detector (optional)

This is the shared Flask store, instrumented for streaming. Every request is
appended to the Redis Stream in an after_request hook (XADD), and a background
thread runs the detector consumer at DEFENSE_LEVEL, exactly as a sidecar worker
would in production. Verdicts land at /admin/verdicts so you can watch them
arrive while you drive traffic.

You do NOT need this running for the checkpoint — tools/checkpoint.py is
self-contained. Use the live app for the demo: run it, hit it with an attack's
--live mode or your browser, and watch the verdict stream.

    REDIS_URL=memory:// DEFENSE_LEVEL=2 python demo_site/app.py

memory:// works here because the app and its consumer thread are one process and
share the same fakeredis. A *separate* consumer process needs real Redis
(docker compose up -d --wait) so the two share a server.
"""

import os
import sys
import threading
import time
from collections import deque

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
for _d in ("demo_site", "defenses"):
    sys.path.insert(0, os.path.join(ROOT, _d))

from flask import Flask, g, jsonify, request, Response

import store
import stream
import consumer

LEVEL = int(os.environ.get("DEFENSE_LEVEL", "0"))
app = Flask(__name__, static_folder="static", static_url_path="/static")
r = store.connect()
stream.reset(r)

_verdicts = deque(maxlen=200)
_stop = threading.Event()


def _on_verdict(v):
    _verdicts.appendleft(v)


if LEVEL >= 1:
    threading.Thread(target=consumer.serve, args=(r, LEVEL, _on_verdict, _stop),
                     daemon=True).start()

PRODUCTS = [{"id": i, "name": f"Sneaker {i}", "price": 90 + i} for i in range(1, 9)]


@app.before_request
def _start():
    g.t0 = time.time()
    g.sid = request.cookies.get("sid") or f"web-{int(time.time()*1000)}-{os.getpid()}"


@app.after_request
def _emit(resp):
    path = request.path
    if not path.startswith("/admin"):
        stream.emit(r, {
            "ts": time.time(), "sid": g.sid, "ip": request.remote_addr or "127.0.0.1",
            "path": path, "method": request.method, "status": resp.status_code,
            "user": (request.form.get("email", "") if request.method == "POST" else ""),
            "ua": request.headers.get("User-Agent", ""), "actor": "live",
        })
    if not request.cookies.get("sid"):
        resp.set_cookie("sid", g.sid, samesite="Lax")
    resp.headers["Server-Timing"] = f"app;dur={(time.time()-g.t0)*1000:.1f}"
    return resp


@app.get("/")
def index():
    return Response(
        "<h1>W3 Ch3 demo store</h1><p>Streaming detection lab. "
        "Verdicts at <a href='/admin/verdicts'>/admin/verdicts</a>.</p>",
        mimetype="text/html")


@app.get("/api/products")
def products():
    return jsonify(PRODUCTS)


@app.get("/api/search")
def search():
    return jsonify([p for p in PRODUCTS if request.args.get("q", "") in p["name"].lower()])


@app.get("/product/<int:pid>")
def product(pid):
    return jsonify(next((p for p in PRODUCTS if p["id"] == pid), {}))


@app.post("/api/login")
def login():
    # Demo rule: the password "correct" succeeds; anything else is a failed login.
    ok = request.form.get("password") == "correct"
    return (jsonify({"ok": True}), 200) if ok else (jsonify({"ok": False}), 401)


@app.post("/api/register")
def register():
    return jsonify({"ok": True}), 200


@app.post("/api/checkout")
def checkout():
    return jsonify({"ok": True}), 200


@app.get("/admin/verdicts")
def verdicts():
    return jsonify({"level": LEVEL, "count": len(_verdicts), "recent": list(_verdicts)[:50]})


@app.post("/admin/reset")
def reset():
    return jsonify({"deleted": stream.reset(r)})


if __name__ == "__main__":
    print(f"demo store on http://localhost:5000  (DEFENSE_LEVEL={LEVEL}, "
          f"store={'memory' if os.environ.get('REDIS_URL','memory://').startswith('memory') else 'redis'})")
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "5000")))
