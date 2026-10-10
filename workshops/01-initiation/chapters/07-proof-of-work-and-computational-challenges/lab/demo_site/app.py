"""
Chapter 7 Lab: the demo store behind a proof-of-work gate.

The catalog (/api/products?page=1..200) is what the scraper wants. From
level 1 on, every catalog request needs a PoW pass, which the client gets
by solving /pow/challenge and posting the answer to /pow/verify. The
browser does this in a Web Worker (static/pow.js); bots do it in Python.

Restart the server with a higher level at each round:

    DEFENSE_LEVEL=0 python app.py     # Round 0: no gate
    DEFENSE_LEVEL=1 python app.py     # + PoW gate, naive verifier
    DEFENSE_LEVEL=2 python app.py     # + signed, expiring, IP-bound challenge
    DEFENSE_LEVEL=3 python app.py     # + single-use challenges, pass budget, pass bound to IP+UA
    DEFENSE_LEVEL=4 python app.py     # + adaptive difficulty from the client's request rate

Storage: Redis from ../docker-compose.yml by default. STORE=memory runs
without Docker (single process only).

Client IP: every lab client sends `X-Sim-Client-IP` so that one laptop can
play a real user, a CGNAT household and a bot farm at once. The server
only trusts that header from loopback, standing in for the edge proxy in
Chapter 3. In production, take the client IP from your edge, never from a
header the client controls.

Debug endpoints (never gated): /pow-check, /pow-bench, POST /lab/reset

Every gated response carries `Server-Timing: pow;dur=<ms>` so the
checkpoint can report what the defense costs us, not just what it catches.
"""

import os
import sys
import time

from flask import Flask, abort, g, jsonify, make_response, render_template_string, request

# Add defenses directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'defenses'))

import adaptive
import challenge_naive
import challenge_signed
import passes
from spend_store import get_store

DEFENSE_LEVEL = int(os.environ.get("DEFENSE_LEVEL", "0"))
BASE_BITS = 16
PAGES = 200
PER_PAGE = 10
PASS_COOKIE = "pow_pass"
LOOPBACK = {"127.0.0.1", "::1"}
UNCOUNTED = {"/pow-check", "/pow-bench", "/lab/reset"}  # debug paths don't count toward the rate

# Restarting the app rotates the secret, which invalidates every pass. Fine for a lab.
SECRET = os.environ.get("POW_SECRET", "").encode() or os.urandom(32)
store = get_store()

app = Flask(__name__)


# --- helpers ----------------------------------------------------------------

def client_ip():
    """The client's IP. The lab header is trusted only from loopback (our 'edge')."""
    sim = request.headers.get("X-Sim-Client-IP")
    if sim and request.remote_addr in LOOPBACK:
        return sim.strip()
    return request.remote_addr


def current_difficulty(record=False):
    """Difficulty this client gets now: fixed until L4, then by request rate."""
    if DEFENSE_LEVEL < 4:
        return BASE_BITS
    rate = store.hit(adaptive.rate_key(g.client_ip), adaptive.WINDOW_S, record=record)
    return adaptive.difficulty_for(rate)


def pass_bind():
    """L3+: a pass only works for the IP + User-Agent that solved it."""
    if DEFENSE_LEVEL < 3:
        return ""
    return challenge_signed.client_bind(g.client_ip, request.headers.get("User-Agent", ""))


def deny(error, reason):
    g.error, g.reasons = error, [reason]
    abort(403)


def check_pass():
    """Gate one catalog request. Returns nothing, or aborts with 403."""
    ok, reason, pid = passes.check(SECRET, request.cookies.get(PASS_COOKIE), pass_bind())
    if not ok:
        deny("pow_required", f"[L{min(DEFENSE_LEVEL, 3)}] {reason}")
    if DEFENSE_LEVEL >= 3:
        used = store.incr(f"pow:pass:{pid}", passes.PASS_TTL)
        if used > passes.PASS_BUDGET:
            deny("pow_required", f"[L3] PoW pass used up ({passes.PASS_BUDGET} requests per solve)")


# --- request hooks -----------------------------------------------------------

@app.before_request
def start_request():
    g.client_ip = client_ip()
    g.pow_ms = 0.0
    g.ops_before = store.ops
    # Count every request toward the client's rate (Round 4 reads it)
    if DEFENSE_LEVEL >= 4 and request.path not in UNCOUNTED and not request.path.startswith("/static"):
        store.hit(adaptive.rate_key(g.client_ip), adaptive.WINDOW_S)


@app.after_request
def report_cost(response):
    if "pow_ms" in g and request.path.startswith(("/api/", "/pow/")):
        ops = store.ops - g.ops_before
        response.headers["Server-Timing"] = f'pow;dur={g.pow_ms:.3f}, store;desc="{ops} ops"'
    return response


# --- the store ---------------------------------------------------------------

INDEX_HTML = """<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Bot Workshop Store</title>
<style>body{font-family:system-ui;max-width:40rem;margin:3rem auto;padding:0 1rem}
code{background:#eee;padding:0 .3rem}#pow{color:#555}</style></head>
<body>
  <h1>Welcome to the store!</h1>
  <p>Defense level: <code>{{ level }}</code> &middot;
     <a href="/pow-check">/pow-check</a> &middot; <a href="/pow-bench">/pow-bench</a></p>
  <noscript><p><b>This store needs JavaScript to check your browser.</b>
     (This is the no-JS false positive. Count it.)</p></noscript>
  <p id="pow">&nbsp;</p>
  <h2>Products, page <span id="page">1</span> of {{ pages }}</h2>
  <ul id="products"><li>Loading&hellip;</li></ul>
  <button id="prev">&larr; prev</button> <button id="next">next &rarr;</button>
  <script src="/static/pow.js"></script>
  <script>
    let page = 1;
    async function show() {
      document.getElementById("page").textContent = page;
      const r = await gatedFetch(`/api/products?page=${page}`);
      const data = await r.json();
      document.getElementById("products").innerHTML = r.ok
        ? data.products.map(p => `<li>${p.name} &mdash; $${p.price}</li>`).join("")
        : `<li>Blocked: ${data.reasons}</li>`;
    }
    document.getElementById("prev").onclick = () => { if (page > 1) { page--; show(); } };
    document.getElementById("next").onclick = () => { if (page < {{ pages }}) { page++; show(); } };
    show();
  </script>
</body>
</html>"""


@app.route("/")
def index():
    return render_template_string(INDEX_HTML, level=DEFENSE_LEVEL, pages=PAGES)


@app.route("/api/products")
def products():
    started = time.perf_counter()
    try:
        if DEFENSE_LEVEL >= 1:
            check_pass()
    finally:
        g.pow_ms = (time.perf_counter() - started) * 1000
    page = max(1, min(PAGES, request.args.get("page", 1, type=int)))
    first = (page - 1) * PER_PAGE + 1
    return jsonify({"page": page, "pages": PAGES, "products": [
        {"id": i, "name": f"Widget #{i}", "price": round(4.99 + (i * 7919 % 9000) / 100, 2)}
        for i in range(first, first + PER_PAGE)
    ]})


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    username = data.get("username", "")
    password = data.get("password", "")
    if username == "admin" and password == "secret":
        return jsonify({"token": "fake-jwt-token-abc123"})
    return jsonify({"error": "Invalid credentials"}), 401


# --- proof of work -----------------------------------------------------------

@app.route("/pow/challenge")
def pow_challenge():
    if DEFENSE_LEVEL == 0:
        return jsonify({"error": "PoW is off at DEFENSE_LEVEL=0"}), 404
    if DEFENSE_LEVEL == 1:
        return jsonify(challenge_naive.issue(BASE_BITS))
    bind = challenge_signed.client_bind(g.client_ip)
    return jsonify(challenge_signed.issue(SECRET, current_difficulty(), bind))


@app.route("/pow/verify", methods=["POST"])
def pow_verify():
    if DEFENSE_LEVEL == 0:
        return jsonify({"error": "PoW is off at DEFENSE_LEVEL=0"}), 404
    started = time.perf_counter()
    body = request.get_json(silent=True) or {}
    challenge, counter = body.get("challenge") or {}, body.get("counter")
    if not isinstance(challenge, dict):
        challenge = {}

    if DEFENSE_LEVEL == 1:
        ok, reason = challenge_naive.verify(challenge, counter)
    else:
        ok, reason = challenge_signed.verify(
            SECRET, challenge, counter, challenge_signed.client_bind(g.client_ip))
    if ok and DEFENSE_LEVEL >= 3:
        # Single use: the first redemption wins, every replay fails.
        # Spend AFTER verifying, or anyone could burn other clients' nonces.
        if not store.spend_once(f"pow:spent:{challenge['nonce']}", challenge_signed.CHALLENGE_TTL):
            ok, reason = False, "[L3] challenge already redeemed (replay)"
    g.pow_ms = (time.perf_counter() - started) * 1000
    if not ok:
        deny("pow_failed", reason)

    ttl = passes.PASS_TTL if DEFENSE_LEVEL >= 3 else passes.PASS_TTL_LONG
    token, _ = passes.issue(SECRET, ttl, pass_bind())
    budget = passes.PASS_BUDGET if DEFENSE_LEVEL >= 3 else None
    resp = make_response(jsonify({"ok": True, "reason": reason, "pass_ttl": ttl,
                                  "pass_budget": budget}))
    resp.set_cookie(PASS_COOKIE, token, max_age=ttl, httponly=True, samesite="Lax")
    return resp


# --- debug endpoints (never gated) ------------------------------------------

@app.route("/pow-check")
def pow_check():
    """Debug endpoint: what does the server see, and what would you pay?"""
    ok, reason, _ = passes.check(SECRET, request.cookies.get(PASS_COOKIE), pass_bind())
    rate = (store.hit(adaptive.rate_key(g.client_ip), adaptive.WINDOW_S, record=False)
            if DEFENSE_LEVEL >= 4 else None)
    return jsonify({
        "level": DEFENSE_LEVEL,
        "store": type(store).__name__,
        "client_ip": g.client_ip,
        "rate_last_60s": rate,
        "difficulty_now": current_difficulty() if DEFENSE_LEVEL >= 1 else None,
        "pass": "valid" if ok else reason,
    })


BENCH_HTML = """<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>PoW bench</title>
<style>body{font-family:system-ui;max-width:40rem;margin:3rem auto;padding:0 1rem}
td,th{padding:.2rem .8rem;text-align:right}</style></head>
<body>
  <h1>How fast is this browser?</h1>
  <p>Runs the store's own solver (pure-JS SHA-256 in Web Workers) for 3 s per row.
     Write the numbers down: Round 0 uses them.</p>
  <button id="go">Run benchmark</button>
  <table><thead><tr><th>workers</th><th>MH/s</th><th>16-bit p50</th><th>16-bit p95</th></tr></thead>
  <tbody id="out"></tbody></table>
  <script src="/static/pow.js"></script>
  <script>
    document.getElementById("go").onclick = async () => {
      const out = document.getElementById("out");
      out.innerHTML = "";
      for (const workers of [1, Math.min(navigator.hardwareConcurrency || 2, 4)]) {
        const rate = await powBenchmark(workers, 3000);
        // geometric distribution: p50 = 0.69 * 2^16, p95 = 3.0 * 2^16 hashes
        const ms = h => (h / rate * 1000).toFixed(0) + " ms";
        out.innerHTML += `<tr><td>${workers}</td><td>${(rate / 1e6).toFixed(2)}</td>` +
                         `<td>${ms(45426)}</td><td>${ms(196327)}</td></tr>`;
      }
    };
  </script>
</body>
</html>"""


@app.route("/pow-bench")
def pow_bench():
    return render_template_string(BENCH_HTML)


@app.route("/lab/reset", methods=["POST"])
def lab_reset():
    """Clear spent nonces, pass budgets and rate windows (the checkpoint calls this)."""
    if request.remote_addr not in LOOPBACK:
        abort(404)
    store.reset()
    return jsonify({"ok": True})


@app.errorhandler(403)
def forbidden(e):
    # Returning the reasons is a teaching aid. In production NEVER tell the
    # attacker which rule fired: it turns your defense into a free oracle.
    return jsonify({
        "error": g.get("error", "forbidden"),
        "reasons": g.get("reasons", []),
    }), 403


if __name__ == "__main__":
    print(f" * Defense level {DEFENSE_LEVEL} · store {type(store).__name__}")
    # PORT: macOS AirPlay Receiver squats on 5000; use e.g. PORT=5050
    app.run(debug=True, port=int(os.environ.get("PORT", "5000")), threaded=True)
