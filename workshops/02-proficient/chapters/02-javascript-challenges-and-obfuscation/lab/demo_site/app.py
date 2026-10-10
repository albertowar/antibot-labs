"""
Chapter 2 Lab: Flask store behind a JavaScript challenge.

DEFENSE_LEVEL picks the challenge. Restart the server with a higher level
at each round:

    DEFENSE_LEVEL=0 python app.py   # Round 0: no challenge
    DEFENSE_LEVEL=1 python app.py   # Round 1: inline JS sets a static cookie
    DEFENSE_LEVEL=2 python app.py   # Round 2: signed, session-bound, single-use nonce
    DEFENSE_LEVEL=3 python app.py   # Round 3: + polymorphic, obfuscated variant pool
    DEFENSE_LEVEL=4 python app.py   # Round 4: + environment-bound answer
    DEFENSE_LEVEL=5 python app.py   # Round 5: + clearance budget (30 requests / 10 min)

Gated paths: / (HTML store) and /api/products (JSON). A client without a valid
clearance gets the challenge page (HTML) or a 403 JSON body (API).

Debug endpoint (never gated): /challenge-check

Storage: Redis from ../docker-compose.yml (REDIS_URL, default
redis://127.0.0.1:6379/0). If Redis isn't reachable, the app falls back to an
in-process fakeredis, so the lab also runs without Docker.

Responses carry Server-Timing (`gate;dur=` or `verify;dur=`) so the checkpoint
can report what the defense costs us, not just what it catches.
"""

import json
import logging
import os
import random
import secrets
import statistics
import sys
import time

from flask import Flask, Response, g, jsonify, render_template, request

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "defenses"))

import clearance
import cookie_gate
import env_integrity
import tokens
import variants

DEFENSE_LEVEL = int(os.environ.get("DEFENSE_LEVEL", "0"))
GATED_PATHS = {"/", "/api/products"}
CLEARANCE_TTL_S = 1800              # levels 2-4; level 5 uses clearance.TTL_S
SECRET = secrets.token_bytes(32)    # new key per start: restarting invalidates old tokens
MANIFEST = os.path.join(os.path.dirname(__file__), "secrets", "manifest.json")
PRODUCTS_PER_PAGE, PAGES = 10, 300

app = Flask(__name__)
if os.environ.get("LOG_REQUESTS") != "1":
    logging.getLogger("werkzeug").setLevel(logging.WARNING)
log = logging.getLogger("challenge")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s", datefmt="%H:%M:%S")


def connect_store():
    import redis
    url = os.environ.get("REDIS_URL", "redis://127.0.0.1:6379/0")
    try:
        store = redis.Redis.from_url(url, socket_connect_timeout=1)
        store.ping()
        return store, url
    except redis.exceptions.ConnectionError:
        import fakeredis
        return fakeredis.FakeRedis(), "fakeredis (in-process; state is lost on restart)"


STORE, STORE_NAME = connect_store()


def load_pool():
    if DEFENSE_LEVEL < 3:
        return {}
    if not os.path.exists(MANIFEST):
        sys.exit("❌ No variant pool. Run `python tools/build_variants.py` from lab/ first.")
    with open(MANIFEST) as f:
        pool = json.load(f)["variants"]
    return {v["id"]: (v["chain"], tuple(v["probe"])) for v in pool}


POOL = load_pool()
L2_SCRIPT = variants.render(variants.L2_CHAIN, variants.L2_PROBE)

ADJECTIVES = ["Quantum", "Rusty", "Silent", "Turbo", "Velvet", "Neon", "Cosmic", "Tiny", "Mega", "Retro"]
NOUNS = ["Widget", "Gadget", "Doohickey", "Sprocket", "Gizmo", "Thingamajig", "Whatsit", "Contraption"]


def product(pid):
    rng = random.Random(pid)
    return {"id": pid, "name": f"{rng.choice(ADJECTIVES)} {rng.choice(NOUNS)} #{pid}",
            "price": round(rng.uniform(2, 250), 2)}


def page_of_products(page):
    start = (page - 1) * PRODUCTS_PER_PAGE + 1
    return [product(pid) for pid in range(start, start + PRODUCTS_PER_PAGE)]


def requested_page():
    try:
        return min(max(int(request.args.get("page", "1")), 1), PAGES)
    except ValueError:
        return 1


# --- the gate --------------------------------------------------------------

def check_request():
    """Return None if the request may pass, else the reason it may not."""
    if DEFENSE_LEVEL == 0:
        return None
    if DEFENSE_LEVEL == 1:
        return None if cookie_gate.passes(request.cookies) else "no valid js_ok cookie"
    payload, reason = tokens.check_clearance(request.cookies.get("clr"), SECRET, g.sid,
                                             request.headers.get("User-Agent"), DEFENSE_LEVEL)
    if payload is None:
        return reason
    if DEFENSE_LEVEL >= 5:
        allowed, used = clearance.consume(STORE, payload)
        g.budget_used = used
        if not allowed:
            return f"clearance budget spent ({clearance.BUDGET}/{clearance.BUDGET})"
    return None


@app.before_request
def gate():
    g.sid = request.cookies.get("sid")
    g.new_sid = g.sid is None
    if g.new_sid:
        g.sid = secrets.token_hex(12)
    if request.path not in GATED_PATHS:
        return None

    started = time.perf_counter()
    reason = check_request()
    g.timing = ("gate", (time.perf_counter() - started) * 1000)
    if reason is None:
        return None

    log.info("challenge  %-14s %s", request.path, reason)
    # Returning the reason is a teaching aid. In production NEVER tell the
    # client why it was challenged: it turns your defense into a free oracle.
    if request.path.startswith("/api/"):
        return jsonify({"error": "challenge_required", "challenge": "/", "reason": reason}), 403
    return render_template("challenge.html", level=DEFENSE_LEVEL, reason=reason,
                           inline_script=cookie_gate.INLINE_SCRIPT), 403


@app.after_request
def finish(response):
    if g.get("new_sid"):
        response.set_cookie("sid", g.sid, httponly=True, samesite="Lax")
    if "timing" in g:
        name, ms = g.timing
        response.headers["Server-Timing"] = f"{name};dur={ms:.3f}"
    response.headers["Cache-Control"] = "no-store"
    return response


# --- the store -------------------------------------------------------------

@app.route("/")
def index():
    page = requested_page()
    return render_template("store.html", level=DEFENSE_LEVEL, page=page, pages=PAGES,
                           products=page_of_products(page))


@app.route("/api/products")
def api_products():
    page = requested_page()
    return jsonify({"page": page, "pages": PAGES, "products": page_of_products(page)})


# --- the challenge ---------------------------------------------------------

@app.route("/challenge/new", methods=["POST"])
def challenge_new():
    if DEFENSE_LEVEL < 2:
        return jsonify({"error": "no challenge at this level"}), 404
    if DEFENSE_LEVEL == 2:
        variant_id, script = "l2", "/challenge/l2.js"
    else:
        variant_id = random.choice(list(POOL))
        script = f"/static/variants/{variant_id}.js"
    nonce, token = tokens.issue_challenge(STORE, SECRET, g.sid, variant_id, DEFENSE_LEVEL)
    return jsonify({"token": token, "nonce": nonce, "env": DEFENSE_LEVEL >= 4, "script": script})


@app.route("/challenge/l2.js")
def challenge_l2_script():
    return Response(L2_SCRIPT, mimetype="application/javascript")


def diagnose(nonce, chain, probe, answer, ua):
    """Teaching aid: work out WHICH environment fact was wrong. Never ship this."""
    width = variants.probe_width(probe)
    for layout in (width, 0):
        for native in (True, False):
            for engine in (variants.ENGINE_V8, variants.ENGINE_OTHER):
                if variants.expected_answer(nonce, chain, (layout, native, engine)) == answer:
                    wrong = []
                    if layout != width:
                        wrong.append("offsetWidth was 0 (no layout engine)")
                    if not native:
                        wrong.append("DOM methods are not native code")
                    if engine != env_integrity.expected_engine(ua):
                        wrong.append("Error.stack style doesn't match the UA's engine")
                    return "; ".join(wrong) or "env matched"
    if variants.expected_answer(nonce, chain) == answer:
        return "answer ignores the environment (a port of the env-less chain?)"
    return "answer doesn't match this variant"


@app.route("/challenge/verify", methods=["POST"])
def challenge_verify():
    started = time.perf_counter()
    data = request.get_json(silent=True) or {}
    ua = request.headers.get("User-Agent")
    payload, reason = tokens.redeem_challenge(STORE, SECRET, data.get("token", ""), g.sid,
                                              DEFENSE_LEVEL)
    if payload is not None:
        if payload["v"] == "l2":
            chain, probe = variants.L2_CHAIN, variants.L2_PROBE
        elif payload["v"] in POOL:
            chain, probe = POOL[payload["v"]]
        else:
            chain = probe = None
            reason = "unknown variant (pool rotated?)"
    elapsed_ms = None
    if payload is not None and chain is not None:
        env = env_integrity.expected_env(probe, ua) if DEFENSE_LEVEL >= 4 else None
        expected = variants.expected_answer(payload["n"], chain, env)
        elapsed_ms = (time.time() - payload["iat"]) * 1000
        answer = str(data.get("answer", ""))
        if not secrets.compare_digest(answer, expected):
            reason = "wrong answer"
            if env is not None:
                reason += f": {diagnose(payload['n'], chain, probe, answer, ua)}"
        elif DEFENSE_LEVEL >= 4 and not env_integrity.within_window(elapsed_ms):
            reason = f"solved in {elapsed_ms:.0f} ms, over the {env_integrity.MAX_SOLVE_MS:.0f} ms window"

    ttl = clearance.TTL_S if DEFENSE_LEVEL >= 5 else CLEARANCE_TTL_S
    verify_ms = (time.perf_counter() - started) * 1000
    if reason is not None:
        log.info("verify     FAIL  %s", reason)
        response = jsonify({"ok": False, "reason": reason, "elapsed_ms": elapsed_ms})
        response.status_code = 403
    else:
        token, _ = tokens.issue_clearance(SECRET, g.sid, ua, DEFENSE_LEVEL, ttl)
        solve_ms = data.get("solve_ms")
        if isinstance(solve_ms, (int, float)):
            STORE.lpush(f"solve_ms:{DEFENSE_LEVEL}", f"{solve_ms:.3f}")
            STORE.ltrim(f"solve_ms:{DEFENSE_LEVEL}", 0, 199)
        log.info("verify     OK    variant=%s", payload["v"])
        # elapsed_ms (challenge issued -> answer received) is reported for the
        # checkpoint's cost table. Another teaching aid: don't echo it in production.
        response = jsonify({"ok": True, "elapsed_ms": round(elapsed_ms, 1)})
        response.set_cookie("clr", token, httponly=True, samesite="Lax", max_age=ttl)
    g.timing = ("verify", verify_ms)
    return response


@app.route("/challenge-check")
def challenge_check():
    """Debug endpoint: the level, your session and your clearance status."""
    payload, reason = tokens.check_clearance(request.cookies.get("clr"), SECRET, g.sid,
                                             request.headers.get("User-Agent"), DEFENSE_LEVEL)
    used = None
    if payload is not None and DEFENSE_LEVEL >= 5:
        used = int(STORE.get(f"budget:{payload['jti']}") or 0)
    solves = [float(x) for x in STORE.lrange(f"solve_ms:{DEFENSE_LEVEL}", 0, -1)]
    return jsonify({
        "level": DEFENSE_LEVEL,
        "store": STORE_NAME,
        "sid": g.sid,
        "clearance": "valid" if payload else reason,
        "budget_used": used,
        "budget": clearance.BUDGET if DEFENSE_LEVEL >= 5 else None,
        "variant_pool": len(POOL),
        "client_solve_ms_median": round(statistics.median(solves), 2) if solves else None,
        "max_solve_ms": env_integrity.MAX_SOLVE_MS if DEFENSE_LEVEL >= 4 else None,
        "naive_engine_check": env_integrity.NAIVE_ENGINE_CHECK if DEFENSE_LEVEL >= 4 else None,
    })


if __name__ == "__main__":
    print(f" * Defense level {DEFENSE_LEVEL} · store: {STORE_NAME}")
    if POOL:
        print(f" * Variant pool: {len(POOL)} obfuscated variants")
    # PORT: macOS AirPlay Receiver squats on 5000; use e.g. PORT=5050
    app.run(port=int(os.environ.get("PORT", "5000")), threaded=True)
