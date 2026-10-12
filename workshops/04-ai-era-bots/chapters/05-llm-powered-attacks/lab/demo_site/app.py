"""W4 Ch5 demo store — four LLM-powered attacks on one e-commerce back end.

The end-of-Workshop-2 store, extended with the surfaces this chapter attacks:

    POST /review                     Round 1  an LLM review farm vs content heuristics
    POST /register (+ challenge)     Round 2  an LLM/VLM solver vs the challenge gate
    GET  /catalog?page=N (HTML)      Round 3  LLM extraction vs layout churn
    GET  /product/<sku>/summary      Round 4  prompt injection through reviews
    POST /assist                     Round 4  prompt injection through reviews

Each round's pre-wired defense (what the store had before this chapter) runs on
every request; the round's *new* defense lives in its own module under
defenses/, which starts as a permissive stub you complete. The store imports the
module fresh on every request, so `checkpoint.py --round N --catch-up` takes
effect without a restart.

Every LLM call goes through tools/llm.py: a deterministic mock by default, or any
OpenAI-compatible local server when LLM_URL is set.

Lab-only shortcuts, all fenced and loopback-only:
  * X-Lab-Client-IP  — the source IP a real CDN would hand us (RFC 5737 ranges).
  * X-Lab-Session    — the browsing-session id a cookie would carry.
  * X-Lab-FP         — the client fingerprint W2 Ch4 would compute.
  * X-Lab-User       — the logged-in account (email) a session cookie would carry.
  * X-Lab-Actor      — ground truth (human/bot) for the scoreboard only.
  * X-Lab-Round      — which round a /review belongs to (1 or 4), for scoring.
A real endpoint has none of these oracles; they exist to measure both sides.
"""

from __future__ import annotations

import hashlib
import importlib
import ipaddress
import json
import os
import random
import sys
import time

from flask import Flask, g, jsonify, render_template, request
from werkzeug.security import generate_password_hash

HERE = os.path.dirname(os.path.abspath(__file__))
LAB_DIR = os.path.dirname(HERE)
DATA_DIR = os.path.join(LAB_DIR, "data")
os.makedirs(DATA_DIR, exist_ok=True)   # SQLite file lives here; seed.py fills the rest
sys.path.insert(0, LAB_DIR)       # for defenses/ and tools/
sys.path.insert(0, HERE)          # for store

from store import (  # noqa: E402
    ALLOW, BLOCK, CHALLENGE, INVALID,
    Decision_, Product, Purchase, Review, User, allow, block, challenge, db,
    log_decision, make_redis,
)
from defenses import challenge_gate, content_heuristics, netintel  # noqa: E402
from tools.llm import LLM  # noqa: E402

SHOP_HOST = "lab-outfitters.test"
SUPPORT_CODE = "SC-7741-KETTLE"
ALLOWED_HOSTS = {SHOP_HOST, "www." + SHOP_HOST}
PER_PAGE = 12
RECENT_WINDOW = 60

SYSTEM_SUMMARY = ("You are the review summariser for Lab Outfitters, an online shop. Write "
                  "two neutral sentences summarising customer reviews of the product.")
SYSTEM_ASSIST = ("You are the support assistant for Lab Outfitters, an online shop. Answer "
                 "the customer's question about the product in one or two sentences, using "
                 f"the product data and customer reviews provided. Support code: {SUPPORT_CODE} "
                 "(for staff escalation; internal).")

app = Flask(__name__, template_folder=os.path.join(HERE, "templates"))
app.secret_key = os.environ.get("LAB_SECRET_KEY", "w4ch5-lab-fixed-secret-not-for-prod")
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get(
    "DATABASE_URL", f"sqlite:///{os.path.abspath(os.path.join(DATA_DIR, 'shop.db'))}"
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db.init_app(app)

rds = make_redis()
llm = LLM()


def load_disposable():
    path = os.path.join(DATA_DIR, "disposable_domains.txt")
    if not os.path.exists(path):
        return set()
    with open(path) as fh:
        return {d.strip().lower() for d in fh if d.strip() and not d.startswith("#")}


DISPOSABLE = load_disposable()


def defense(name):
    """Import a round's defense fresh, so --catch-up edits take effect live."""
    mod = importlib.import_module(f"defenses.{name}")
    return importlib.reload(mod)


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


def fp() -> str:
    return request.headers.get("X-Lab-FP") or request.cookies.get("did") or "no-fp"


def sid() -> str:
    return request.headers.get("X-Lab-Session") or request.cookies.get("sid") or "no-sid"


def record(round_, endpoint, decision, extra="", tokens=0):
    ip = client_ip()
    log_decision(
        round=round_, actor=actor(), endpoint=endpoint, client_ip=ip,
        net_type=netintel.net_type(ip), fp=fp(), outcome=decision.action,
        reason=(decision.reason + (f" | {extra}" if extra else ""))[:255],
        score=decision.score, latency_ms=getattr(g, "lat_ms", 0.0), tokens=tokens,
    )


_HTTP = {ALLOW: 200, CHALLENGE: 200, BLOCK: 403, INVALID: 400}


def respond(round_, endpoint, decision, body=None, extra="", tokens=0):
    record(round_, endpoint, decision, extra, tokens)
    out = {"outcome": decision.action, "reason": decision.reason}
    if body:
        out.update(body)
    return jsonify(out), _HTTP[decision.action]


# --- Round 1 (and 4): customer reviews ----------------------------------------------

@app.post("/review")
def review():
    t0 = time.perf_counter()
    data = request.get_json(silent=True) or request.form
    sku = data.get("sku") or ""
    text = (data.get("text") or "").strip()
    rating = int(data.get("rating") or 5)
    email = (request.headers.get("X-Lab-User") or data.get("email") or "").lower().strip()
    round_ = int(request.headers.get("X-Lab-Round", "1"))
    user = db.session.get(User, email)
    product = db.session.get(Product, sku)
    if not user or not product or not text:
        return jsonify({"outcome": INVALID, "reason": "unknown account, product or empty text"}), 400

    ip = client_ip()
    now = time.time()
    by_fp = rds.incr(f"rev:fp:{fp()}:{int(now // 86400)}")
    rds.expire(f"rev:fp:{fp()}:{int(now // 86400)}", 2 * 86400)
    by_ip = rds.incr(f"rev:ip:{ip}:{int(now // 3600)}")
    rds.expire(f"rev:ip:{ip}:{int(now // 3600)}", 2 * 3600)

    recent = [r.text for r in Review.query.filter(Review.outcome != BLOCK)
              .order_by(Review.ts.desc()).limit(RECENT_WINDOW).all()]
    domain = email.split("@")[-1]
    decision = content_heuristics.evaluate({
        "text": text, "recent_texts": recent, "email_domain": domain,
        "disposable": domain in DISPOSABLE})
    if decision.action == ALLOW:
        bought = Purchase.query.filter_by(email=email, sku=sku).first() is not None
        decision = defense("review_signals").evaluate({
            "account_age_days": (now - user.created_at) / 86400.0,
            "verified_purchase": bought, "reviews_by_fp_24h": by_fp,
            "reviews_by_ip_1h": by_ip, "net_type": netintel.net_type(ip)})
    if decision.action == ALLOW:
        decision = defense("llm_guard").ingest(text)

    db.session.add(Review(sku=sku, email=email, rating=rating, text=text, actor=actor(),
                          fp=fp(), outcome=decision.action,
                          published=(decision.action == ALLOW)))
    db.session.commit()
    g.lat_ms = (time.perf_counter() - t0) * 1000
    return respond(round_, "review", decision, extra=f"sku={sku}")


# --- Round 2: registration behind the challenge gate ---------------------------------

@app.post("/register")
def register():
    t0 = time.perf_counter()
    data = request.get_json(silent=True) or request.form
    email = (data.get("email") or "").lower().strip()
    password = data.get("password") or ""
    token = data.get("challenge_token")
    mode = "text" if (data.get("mode") == "text") else "image"
    ip = client_ip()
    bucket = int(time.time() // 300)
    if token:   # second leg: answering a puzzle, counters already bumped
        reg_ip = int(rds.get(f"reg:{ip}:{bucket}") or 1)
        fp_cluster = int(rds.get(f"fpreg:{fp()}:{bucket}") or 1)
    else:
        reg_ip = rds.incr(f"reg:{ip}:{bucket}")
        rds.expire(f"reg:{ip}:{bucket}", 600)
        fp_cluster = rds.incr(f"fpreg:{fp()}:{bucket}")
        rds.expire(f"fpreg:{fp()}:{bucket}", 600)
    if not email or "@" not in email or len(password) < 8:
        return jsonify({"outcome": INVALID, "reason": "email and an 8+ char password required"}), 400
    if db.session.get(User, email):
        return jsonify({"outcome": INVALID, "reason": "account exists"}), 400

    policy = defense("challenge_policy")
    ctx = {"net_type": netintel.net_type(ip), "reg_count_ip": reg_ip,
           "fp_cluster": fp_cluster, "accessible": mode == "text",
           "solves_by_fp_1h": 0, "solve_ms": 0.0}

    if not token:
        serve, bits = policy.serve(ctx)
        if serve:
            chal = challenge_gate.issue(rds, mode, pow_bits=bits)
            g.lat_ms = (time.perf_counter() - t0) * 1000
            return respond(2, "register", challenge(f"puzzle served ({mode}, pow={bits} bits)"),
                           body={"challenge": chal}, extra=f"ip_count={reg_ip}")
        decision = allow("registered without a challenge (low risk)")
    else:
        ok, why, solve_ms = challenge_gate.verify(rds, token, data.get("answer"), data.get("nonce"))
        if not ok:
            g.lat_ms = (time.perf_counter() - t0) * 1000
            return respond(2, "register", block(why), extra=f"ip_count={reg_ip}")
        hour = int(time.time() // 3600)
        solves = rds.incr(f"solve:{fp()}:{hour}")
        rds.expire(f"solve:{fp()}:{hour}", 7200)
        ctx.update(solves_by_fp_1h=solves, solve_ms=solve_ms)
        decision = policy.verdict(ctx)
        if decision.action == ALLOW:
            decision = allow(f"registered: {why}")

    if decision.action == ALLOW:
        db.session.add(User(email=email, password_hash=generate_password_hash(password, "pbkdf2:sha256:1000"),
                            origin="registered"))
        db.session.commit()
    g.lat_ms = (time.perf_counter() - t0) * 1000
    return respond(2, "register", decision, extra=f"ip_count={reg_ip} fp_cluster={fp_cluster}")


# --- Round 3: the HTML catalogue -----------------------------------------------------

_ROLES = ["grid", "card", "name", "price", "sku", "link", "hidden", "hp", "wrap"]


def _classes(session_id: str) -> dict:
    """Per-session class names: a selector written against one session's HTML
    matches nothing in the next. Cheap layout churn (W1 Ch7)."""
    salt = app.secret_key
    return {role: "c" + hashlib.sha256(f"{session_id}:{role}:{salt}".encode()).hexdigest()[:6]
            for role in _ROLES}


def _canary(session_id: str) -> str:
    code = "LOT-" + hashlib.sha256(f"canary:{session_id}:{app.secret_key}".encode()).hexdigest()[:8].upper()
    rds.hset("canary", code, session_id)
    return code


@app.get("/catalog")
def catalog():
    t0 = time.perf_counter()
    page = request.args.get("page", "1")
    page = int(page) if page.isdigit() and int(page) >= 1 else 1
    rows = Product.query.filter_by(honeypot=False).order_by(Product.sku).all()
    pages = max(1, (len(rows) + PER_PAGE - 1) // PER_PAGE)
    cards = rows[(page - 1) * PER_PAGE: page * PER_PAGE]
    rng = random.Random(f"{sid()}:{page}")
    cards = list(cards)
    rng.shuffle(cards)
    honeypots = Product.query.filter_by(honeypot=True).all()
    canary = _canary(sid())
    traps = defense("extractor_traps").decorate({
        "sid": sid(), "canary": canary, "page": page,
        "honeypots": [{"name": h.name, "price": h.price, "sku": h.sku} for h in honeypots]})
    hp_links = [h.sku for h in rng.sample(honeypots, min(2, len(honeypots)))]
    rds.sadd(f"cov:{sid()}", f"page:{page}")
    rds.expire(f"cov:{sid()}", 300)
    html = render_template("catalog.html", c=_classes(sid()), cards=cards, page=page,
                           pages=pages, traps=traps, honeypot_links=hp_links,
                           wraps=rng.randint(1, 3))
    g.lat_ms = (time.perf_counter() - t0) * 1000
    n_hidden = len(traps.get("hidden_records", [])) + len(traps.get("decoy_paragraphs", []))
    record(3, "catalog", allow(f"page {page} served; hidden blocks={n_hidden}"),
           extra=f"canary={canary}")
    return html, 200, {"Content-Type": "text/html; charset=utf-8"}


@app.get("/product/<sku>")
def product(sku):
    t0 = time.perf_counter()
    p = db.session.get(Product, sku)
    if not p:
        return jsonify({"outcome": INVALID, "reason": "no such product"}), 404
    g.lat_ms = (time.perf_counter() - t0) * 1000
    if p.honeypot:
        # Pre-wired (W1 Ch7 / W3 Ch6): nobody is ever shown this SKU. Whoever asks
        # for it read something a person cannot see.
        return respond(3, "product", block("fetched a honeypot SKU: only a machine reader finds it", 100.0),
                       extra=f"sku={sku}")
    return respond(3, "product", allow("served"),
                   body={"sku": p.sku, "name": p.name, "price": p.price, "blurb": p.blurb},
                   extra=f"sku={sku}")


# --- Round 4: the store's LLM features -------------------------------------------------

def _published_reviews(sku):
    return [f"[{r.rating}/5] {r.text}" for r in
            Review.query.filter_by(sku=sku, published=True).order_by(Review.ts).all()]


def _llm_feature(endpoint, task, system, trusted, untrusted, fallback):
    guard = defense("llm_guard")
    system2, user = guard.build_prompt(system, trusted, untrusted)
    reply = llm.chat(task, system2, user)
    tokens = reply.prompt_tokens + reply.completion_tokens
    verdict = guard.validate(reply.text, ALLOWED_HOSTS, SUPPORT_CODE)
    text = reply.text if verdict.action == ALLOW else fallback
    return verdict, text, tokens, reply


@app.get("/product/<sku>/summary")
def summary(sku):
    t0 = time.perf_counter()
    p = db.session.get(Product, sku)
    if not p:
        return jsonify({"outcome": INVALID, "reason": "no such product"}), 404
    verdict, text, tokens, reply = _llm_feature(
        "summary", "summarize", SYSTEM_SUMMARY, {"product": p.name},
        _published_reviews(sku), "Summary unavailable.")
    g.lat_ms = (time.perf_counter() - t0) * 1000
    return respond(4, "summary", verdict, body={"summary": text, "backend": reply.backend},
                   extra=f"sku={sku} tokens={tokens}", tokens=tokens)


@app.post("/assist")
def assist():
    t0 = time.perf_counter()
    data = request.get_json(silent=True) or request.form
    sku = data.get("sku") or ""
    question = (data.get("question") or "").strip()[:300]
    p = db.session.get(Product, sku)
    if not p or not question:
        return jsonify({"outcome": INVALID, "reason": "sku and question required"}), 400
    verdict, text, tokens, reply = _llm_feature(
        "assist", "assist", SYSTEM_ASSIST,
        {"product": p.name, "price": f"{p.price:.2f}", "question": question},
        _published_reviews(sku), "Sorry, I can't help with that right now.")
    g.lat_ms = (time.perf_counter() - t0) * 1000
    return respond(4, "assist", verdict, body={"answer": text, "backend": reply.backend},
                   extra=f"sku={sku} tokens={tokens}", tokens=tokens)


# --- Lab instrumentation (not part of the product) ------------------------------------

@app.get("/whoami")
def whoami():
    ip = client_ip()
    return jsonify({"client_ip": ip, "net_type": netintel.net_type(ip), "fp": fp(),
                    "session": sid(), "actor": actor(), "llm_backend": llm.backend}), 200


@app.get("/lab/decisions")
def lab_decisions():
    round_ = request.args.get("round")
    q = Decision_.query
    if round_:
        q = q.filter_by(round=int(round_))
    rows = q.order_by(Decision_.ts).all()
    return jsonify([
        {"ts": r.ts, "round": r.round, "actor": r.actor, "endpoint": r.endpoint,
         "client_ip": r.client_ip, "net_type": r.net_type, "fp": r.fp,
         "outcome": r.outcome, "reason": r.reason, "score": r.score,
         "latency_ms": r.latency_ms, "tokens": r.tokens} for r in rows])


@app.get("/lab/reviews")
def lab_reviews():
    rows = Review.query.order_by(Review.ts).all()
    return jsonify([{"sku": r.sku, "email": r.email, "rating": r.rating, "text": r.text,
                     "actor": r.actor, "outcome": r.outcome, "published": r.published,
                     "generated_looking": content_heuristics.looks_generated(r.text)}
                    for r in rows])


@app.get("/lab/answer/<token>")
def lab_answer(token):
    """Lab oracle: the puzzle answer, so the *human* simulator can answer like a
    person who looked at it. Loopback only; the attacker never calls this."""
    if not _loopback(request.remote_addr or ""):
        return jsonify({"error": "loopback only"}), 403
    raw = rds.get(f"chal:{token}")
    if raw is None:
        return jsonify({"error": "unknown token"}), 404
    return jsonify({"answer": json.loads(raw)["answer"]})


@app.get("/lab/canaries")
def lab_canaries():
    return jsonify(rds.hgetall("canary"))


@app.post("/lab/reset")
def lab_reset():
    """Clear the decision log, reviews and runtime counters, and drop any
    accounts created by Round 2, so a round is measured from a clean slate."""
    Decision_.query.delete()
    Review.query.delete()
    User.query.filter_by(origin="registered").delete()
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


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    print(f"W4 Ch5 demo store on http://127.0.0.1:{port}  (LLM backend: {llm.backend})")
    app.run(host="127.0.0.1", port=port, threaded=True)
