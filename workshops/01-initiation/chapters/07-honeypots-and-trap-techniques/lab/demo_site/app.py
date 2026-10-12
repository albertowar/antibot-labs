"""
Chapter 7 Lab: the demo store with honeypots and traps.

Restart the server with a higher DEFENSE_LEVEL at each round:

    DEFENSE_LEVEL=0 python app.py     # Round 0: no traps, log only
    DEFENSE_LEVEL=1 python app.py     # + classic hidden form field (inline display:none)
    DEFENSE_LEVEL=2 python app.py     # + CSS-hidden honeypot, opaque field names, timing token
    DEFENSE_LEVEL=3 python app.py     # + trap link, honey record, decoy endpoints, robots.txt
    DEFENSE_LEVEL=4 python app.py     # + sanctions: RESPONSE_MODE and SANCTION_KEY

Levels 1-3 detect: a trapped signup gets a fake success page and is not saved.
Level 4 also sanctions the client for 15 minutes. How, and keyed on what, is set
by RESPONSE_MODE=block|fake|quarantine and SANCTION_KEY=ip|session
(defenses/responses.py).

Client IPs: lab clients send X-Forwarded-For with a TEST-NET address
(RFC 5737), and the app trusts it only from loopback. That stands in for the
trusted edge proxy from W1 Ch2, so one laptop can play many networks.

Debug endpoints (never trapped or sanctioned): /trap-check, /trap-logs,
/lab/summary, POST /lab/reset.

Storage: Redis from ../docker-compose.yml by default. Set REDIS_URL=memory://
to run without Docker.

Every response carries `Server-Timing: trapcheck;dur=<ms>` so the checkpoint
can report what the traps cost us, not just what they catch.
"""

import os
import secrets
import sys
import time
from html import escape

from flask import Flask, Response, abort, g, jsonify, render_template_string, request, session

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "defenses"))

import crawl_traps
import form_traps
import responses
import trap_store as store

DEFENSE_LEVEL = int(os.environ.get("DEFENSE_LEVEL", "0"))
SECRET = os.environ.get("SECRET_KEY", "w1-ch07-lab-only-secret")
EXEMPT_PREFIXES = ("/trap-check", "/trap-logs", "/lab/", "/static/")
LOOPBACK = {"127.0.0.1", "::1"}

app = Flask(__name__)
app.secret_key = SECRET

PRODUCTS = {
    1: ("Trail Thermos 750 ml", 29.99),
    2: ("Cast Iron Skillet 26 cm", 44.50),
    3: ("Merino Hiking Socks", 18.00),
    4: ("Pour-Over Coffee Kit", 36.75),
    5: ("Bamboo Cutting Board", 22.40),
    6: ("Waxed Canvas Tote", 58.00),
    7: ("Enamel Camp Mug", 12.95),
    8: ("LED Headlamp 400 lm", 31.20),
    9: ("Linen Apron", 27.00),
    10: ("Folding Camp Stool", 39.99),
    11: ("Chef's Knife 20 cm", 89.00),
    12: ("Beeswax Food Wraps (3)", 15.50),
}
# Never linked from any page. Only id enumeration finds it (level 3+).
HONEY_PRODUCT = ("Seafoam Glaze Espresso Cup", 17.49)


def client_ip():
    """The simulated edge: trust the rightmost X-Forwarded-For hop from loopback only."""
    forwarded = request.headers.get("X-Forwarded-For")
    if request.remote_addr in LOOPBACK and forwarded:
        return forwarded.split(",")[-1].strip()
    return request.remote_addr


def exempt():
    return request.path.startswith(EXEMPT_PREFIXES)


def product(pid):
    if pid in PRODUCTS:
        return PRODUCTS[pid]
    if pid == crawl_traps.HONEY_PRODUCT_ID and DEFENSE_LEVEL >= 3:
        return HONEY_PRODUCT
    return None


def hit(trap, detail=""):
    """Record a trap hit. At level 4, also sanction the client."""
    store.record_event(g.actor, g.ip, g.sid, trap, request.path, detail)
    if DEFENSE_LEVEL >= 4:
        store.sanction(*responses.sanction_target(g.ip, g.sid), trap)
        g.sanctioned = trap


@app.before_request
def traps_and_sanctions():
    session.setdefault("sid", secrets.token_hex(8))
    g.ip, g.sid = client_ip(), session["sid"]
    # Scoreboard label only: set by the lab scripts, never read by a defense.
    g.actor = request.headers.get("X-Lab-Actor", "browser")
    g.trap_ms, g.sanctioned = 0.0, None
    if exempt():
        return

    store.count(g.actor, "requests")
    started = time.perf_counter()
    trap = crawl_traps.trap_for(request.path, DEFENSE_LEVEL)
    if trap:
        hit(trap)
    if DEFENSE_LEVEL >= 4 and not g.sanctioned:
        g.sanctioned = store.sanctioned(*responses.sanction_target(g.ip, g.sid))
    g.trap_ms += (time.perf_counter() - started) * 1000

    if g.sanctioned and responses.mode(DEFENSE_LEVEL) == "block":
        abort(403)


@app.after_request
def report_cost(response):
    if not exempt():
        response.headers["Server-Timing"] = f"trapcheck;dur={g.trap_ms:.3f}"
        store.add_timing(g.trap_ms)
    return response


LAYOUT = """<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>{{ title }} · Workshop Store</title>
<link rel="stylesheet" href="/static/store.css"></head>
<body>
<header>
  <a class="brand" href="/">Workshop Store</a>
  <nav><a href="/register">Create account</a> <a href="/login">Sign in</a>
  {% if user %}<span class="user">Signed in as {{ user }}</span>{% endif %}</nav>
</header>
<main>{{ body|safe }}</main>
<footer>
  <span>Defense level {{ level }}</span> &middot;
  <a href="/trap-check">/trap-check</a> &middot; <a href="/trap-logs">/trap-logs</a>
  {{ trap_link|safe }}
</footer>
<script src="/static/store.js"></script>
</body>
</html>"""


def page(title, body, status=200):
    html = render_template_string(
        LAYOUT, title=title, body=body, level=DEFENSE_LEVEL, user=session.get("user"),
        trap_link=crawl_traps.trap_link_html(DEFENSE_LEVEL))
    return html, status


def result(outcome, message, status=200):
    """Bots and personas read data-outcome. Real and fake outcomes must look identical."""
    return page("Result", f'<p id="result" data-outcome="{outcome}">{message}</p>', status)


# --- Store pages --------------------------------------------------------------

@app.route("/")
def index():
    items = "".join(
        f'<li><a href="/products/{pid}">{escape(name)}</a> <span class="price">${price:.2f}</span></li>'
        for pid, (name, price) in PRODUCTS.items())
    return page("Catalog", f'<h1>Catalog</h1><ul class="catalog">{items}</ul>')


@app.route("/products/<int:pid>")
def product_page(pid):
    item = product(pid)
    if not item:
        abort(404)
    name, price = item
    me = session.get("user")
    reviews = "".join(
        f'<li class="review"><b>{escape(rv["author"])}</b>: {escape(rv["text"])}</li>'
        # Shadow ban: a suppressed review is shown to its author only
        for rv in store.reviews_for(pid) if rv["published"] or rv["author"] == me)
    form = ""
    if me:
        form = (f'<form id="review" method="post" action="/review">'
                f'<input type="hidden" name="product_id" value="{pid}">'
                f'<label for="text">Your review</label><textarea id="text" name="text" required></textarea>'
                f'<button type="submit">Post review</button></form>')
    body = (f'<h1 id="product-name">{escape(name)}</h1><p id="product-price">${price:.2f}</p>'
            f'<h2>Reviews</h2><ul id="reviews">{reviews}</ul>{form}')
    return page(name, body)


@app.route("/api/products")
def api_products():
    return jsonify({"products": [{"id": pid, "name": n, "price": p}
                                 for pid, (n, p) in PRODUCTS.items()]})


@app.route("/api/products/<int:pid>")
def api_product(pid):
    item = product(pid)
    if not item:
        abort(404)
    return jsonify({"id": pid, "name": item[0], "price": item[1]})


@app.route("/robots.txt")
def robots():
    return Response(crawl_traps.robots_txt(DEFENSE_LEVEL), mimetype="text/plain")


# --- Signup, login, reviews ---------------------------------------------------

SIGNUP_FORM = """<h1>Create account</h1>
<form id="signup" method="post" action="/register">
{fields}
<button type="submit">Create account</button>
</form>"""


@app.route("/register", methods=["GET"])
def register_form():
    fields = form_traps.render_fields(SECRET, g.sid, DEFENSE_LEVEL)
    return page("Create account", SIGNUP_FORM.format(fields=fields))


@app.route("/register", methods=["POST"])
def register_submit():
    started = time.perf_counter()
    store.count(g.actor, "signup_attempts")
    values, reasons, expired = form_traps.check_submission(
        request.form, SECRET, g.sid, DEFENSE_LEVEL)
    for reason in reasons:
        hit(reason, "signup")
    g.trap_ms += (time.perf_counter() - started) * 1000

    if expired:
        store.count(g.actor, "signup_expired")
        fields = form_traps.render_fields(SECRET, g.sid, DEFENSE_LEVEL)
        body = ('<p id="result" data-outcome="expired">This form expired. Please try again.</p>'
                + SIGNUP_FORM.format(fields=fields))
        return page("Create account", body)

    username, password = values["username"], values["password"]
    welcome = (f"Welcome aboard, {escape(username or 'friend')}! "
               'You can now <a href="/login">sign in</a>.')

    if reasons or g.sanctioned:
        mode = responses.mode(DEFENSE_LEVEL)
        if mode == "block":
            abort(403)
        if mode == "quarantine" and username and password and \
                store.create_account(username, password, status="quarantined"):
            store.count(g.actor, "signup_quarantined")
        else:
            # detect / fake: nothing is saved. Same page, same status as a real signup.
            store.count(g.actor, "signup_trapped")
        return result("created", welcome)

    if not username or not password:
        return result("error", "Username and password are required.", 400)
    if not store.create_account(username, password):
        return result("error", "That username is taken.", 400)
    store.count(g.actor, "signup_created")
    return result("created", welcome)


LOGIN_FORM = """<h1>Sign in</h1>
<form id="signin" method="post" action="/login">
<div class="field"><label for="username">Username</label>
<input type="text" id="username" name="username" autocomplete="username" required></div>
<div class="field"><label for="password">Password</label>
<input type="password" id="password" name="password" autocomplete="current-password" required></div>
<button type="submit">Sign in</button>
</form>"""


@app.route("/login", methods=["GET"])
def login_form():
    # No timing trap here: password managers submit login forms in well under a second.
    return page("Sign in", LOGIN_FORM)


@app.route("/login", methods=["POST"])
def login_submit():
    username = request.form.get("username", "")
    account = store.get_account(username)
    if not account or account["password"] != request.form.get("password", ""):
        store.count(g.actor, "login_failed")
        return result("invalid", "Invalid username or password.", 401)
    session["user"] = username
    store.count(g.actor, "login_ok")
    return result("signed-in", f"Signed in as {escape(username)}.")


@app.route("/review", methods=["POST"])
def review_submit():
    user = session.get("user")
    if not user:
        return result("invalid", "Please sign in first.", 401)
    pid = request.form.get("product_id", type=int)
    if not product(pid):
        abort(404)
    account = store.get_account(user) or {}
    contained = account.get("status") == "quarantined" or g.sanctioned
    if contained and responses.mode(DEFENSE_LEVEL) == "fake":
        store.count(g.actor, "review_dropped")
    else:
        store.add_review(pid, user, request.form.get("text", "")[:500], published=not contained)
        store.count(g.actor, "review_suppressed" if contained else "review_published")
    # Identical response either way
    return result("review-posted", f'Thanks! Your review is live. <a href="/products/{pid}">Back</a>')


# --- Crawl traps: decoys that only exist from level 3 -------------------------
# The hit itself is recorded in before_request. These routes only decide what
# the trapped client sees: something plausible, never an error that says "trap".

@app.route("/catalog/archive")
@app.route("/catalog/archive/<int:page_no>")
def archive(page_no=1):
    if DEFENSE_LEVEL < 3:
        abort(404)
    links = "".join(f'<li><a href="/catalog/archive/{n}">Archive page {n}</a></li>'
                    for n in range(page_no + 1, page_no + 4))
    return page("Archive", f"<h1>Archived products, page {page_no}</h1><ul>{links}</ul>")


@app.route("/.env")
def dotenv():
    if DEFENSE_LEVEL < 3:
        abort(404)
    # Canary values: if these ever show up in a login attempt, you know where they came from.
    body = "APP_ENV=production\nDB_HOST=db.internal\nDB_PASSWORD=canary-7f3a9c\n"
    return Response(body, mimetype="text/plain")


@app.route("/wp-admin/")
@app.route("/wp-login.php")
def wordpress():
    if DEFENSE_LEVEL < 3:
        abort(404)
    return page("Log In", LOGIN_FORM.replace('action="/login"', 'action="/wp-login.php"'))


@app.route("/api/internal/<path:rest>")
def internal_api(rest):
    if DEFENSE_LEVEL < 3:
        abort(404)
    return jsonify({"error": "unauthorized"}), 401


# --- Debug endpoints ----------------------------------------------------------

@app.route("/trap-check")
def trap_check():
    """How the store sees YOU: your simulated IP, session and any sanction."""
    return jsonify({
        "level": DEFENSE_LEVEL,
        "response_mode": responses.mode(DEFENSE_LEVEL),
        "sanction_key": responses.SANCTION_KEY if DEFENSE_LEVEL >= 4 else None,
        "client_ip": g.ip,
        "session_id": g.sid,
        "sanctioned": store.sanctioned(*responses.sanction_target(g.ip, g.sid)),
        "honeypot": form_traps.HONEYPOT if DEFENSE_LEVEL >= 2 else None,
        "min_fill_seconds": form_traps.MIN_FILL_SECONDS if DEFENSE_LEVEL >= 2 else None,
        "robots_disallow": crawl_traps.ROBOTS_DISALLOW if DEFENSE_LEVEL >= 3 else None,
    })


@app.route("/trap-logs")
def trap_logs():
    return jsonify(store.recent_events(50))


@app.route("/lab/summary")
def lab_summary():
    return jsonify(store.summary())


@app.route("/lab/reset", methods=["POST"])
def lab_reset():
    store.reset()
    return jsonify({"reset": True})


@app.errorhandler(403)
def forbidden(e):
    store.count(g.get("actor", "browser"), "blocked")
    # Showing the reason is a teaching aid. In production, never tell a client
    # which trap caught it: that turns the trap into a free oracle.
    reason = escape(str(g.get("sanctioned") or "sanctioned"))
    return result("blocked", f"Request blocked ({reason}).", 403)


if __name__ == "__main__":
    print(f" * Defense level {DEFENSE_LEVEL}, response mode {responses.mode(DEFENSE_LEVEL)}"
          + (f", sanction key {responses.SANCTION_KEY}" if DEFENSE_LEVEL >= 4 else ""))
    # PORT: macOS AirPlay Receiver squats on 5000; use e.g. PORT=5050
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "5000")), debug=os.environ.get("LAB_DEBUG") == "1", use_reloader=True)
