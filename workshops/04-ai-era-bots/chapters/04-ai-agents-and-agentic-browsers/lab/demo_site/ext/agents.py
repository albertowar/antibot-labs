"""W4 Ch4 extension: what an agent-aware store needs around the checks.

The checks (defenses/) decide; this module gives them something to decide about and enacts what
the closed verdict set cannot say. Everything here is ext-only; no starter file is edited.

  Telemetry   `hooks.telemetry.register("agent", ...)`: the collector (static/js/agent.js) posts a
              fingerprint and, per page, the pointer / key / scroll / overlay events. The sink keeps
              only the latest payload per kind, so the handler accumulates one entry per page
              (defenses/agent_session.py). The server's own flow log is an enricher.
  Challenge   `step_up`: a 6-digit code "emailed" to the account (the lab mailbox,
              GET /lab/mailbox/<email>), the hand-off every agentic browser already does at payment.
              A `challenge` verdict is how Round 2 (robotic session) and Round 4 (new account) ask
              a person to confirm; one solve absorbs one verdict (`uses=1`).
  Mandates    POST/GET /api/account/mandates: the account holder, in their own session, lets one
              operator buy one SKU once, soon. An agent session cannot grant one.
  Policy      GET /agent-policy (ungated: it is the first thing an agent reads) and the Markdown
              catalogue for declared agents (`Accept: text/markdown`), a `before_request` registered
              AFTER the gate's, so it only sees what the gate allowed.
  After a buy `hooks.on_action("drop_buy", ...)` runs once the order is committed: it stamps the order
              with who placed it (human / declared / verified agent), spends the mandate and counts
              the unit against the device. Refusing a purchase is the gate's job, not this hook's:
              by the time it runs the stock is already gone.
  Identity    The Web Bot Auth verifier needs the operators' key directories. tools/mock_internet.py
              plays both synthetic operators on 127.0.0.1:5004; this module starts it on a thread
              unless one of ours already answers at MOCK_URL (MOCK_AUTOSTART=0 to run it yourself; a
              busy port falls back to a free one). The verifier also needs the raw query string and the
              scheme, which `ctx.args` has lost: an enricher exposes them as ctx.attrs["raw_query"] and
              ["scheme"], the way W4 Ch2's ext does.
  Reset       POST /lab/reset also resets the mock's counters; the mandates, mailboxes and device
              counters live in Redis under `lab:` and go with it.
"""

import hmac
import importlib
import json
import os
import secrets
import socket
import sys
import threading
import time

import httpx
from flask import Blueprint, Response, current_app, g, jsonify, request

import labnet

from .. import hooks
from ..models import Product, db
from ..routes import api_error, current_user

LAB = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
bp = Blueprint("agents", __name__)
STEP_UP = "step_up"
STEP_UP_TTL = 600
STEP_UP_TRIES = 5


def _d(name):
    """A defense module, looked up at call time (the reloader reloads in place; a held reference would go stale)."""
    return importlib.import_module(f"defenses.{name}")


# --- the operators' websites (side service) ----------------------------------------------------

def _is_ours(url):
    try:
        r = httpx.get(f"{url}/stats", timeout=1)
        return r.status_code == 200 and r.json().get("mock") == "w4ch4"
    except (httpx.HTTPError, ValueError):
        return False


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def start_mock():
    """Make sure the operators' websites are answering; sets and returns MOCK_URL."""
    url = os.environ.get("MOCK_URL", f"http://127.0.0.1:{os.environ.get('MOCK_PORT', '5004')}").rstrip("/")
    labnet.require_local(url, what="MOCK_URL")
    if os.environ.get("MOCK_AUTOSTART", "1") == "0" or _is_ours(url):
        os.environ["MOCK_URL"] = url
        return url
    sys.path[:0] = [os.path.join(LAB, "tools")]
    import mock_internet
    from werkzeug.serving import make_server
    port = int(url.rsplit(":", 1)[1])
    try:
        srv = make_server("127.0.0.1", port, mock_internet.app, threaded=True)
    except OSError:
        port = _free_port()
        srv = make_server("127.0.0.1", port, mock_internet.app, threaded=True)
    threading.Thread(target=srv.serve_forever, daemon=True, name="mock-internet").start()
    os.environ["MOCK_URL"] = f"http://127.0.0.1:{port}"
    return os.environ["MOCK_URL"]


def _reset_mock(app):
    try:
        httpx.post(f"{os.environ['MOCK_URL']}/reset", timeout=2)
    except httpx.HTTPError:
        pass


# --- enrichers: what the checks need and ctx.args has lost -----------------------------------------

def _enrich(ctx):
    ctx.attrs["raw_query"] = request.query_string.decode("latin-1")
    ctx.attrs["scheme"] = request.scheme
    if ctx.method == "GET" and not ctx.path.startswith("/api/"):
        _d("agent_session").record_flow(ctx)


# --- the step-up challenge ---------------------------------------------------------------------

def _mask(email):
    name, _, domain = email.partition("@")
    return f"{name[:2]}***@{domain}" if domain else "your account email"


def _email_of(ctx):
    if ctx.user is not None:
        return ctx.user.email
    body = ctx.json if isinstance(ctx.json, dict) else {}
    return str(ctx.form.get("email") or body.get("email") or "").strip().lower()


def _stepup_issue(ctx):
    email = _email_of(ctx)
    code = f"{secrets.randbelow(10 ** 6):06d}"
    r, sid = ctx.redis, ctx.session.sid
    r.set(f"lab:agent:stepup:{sid}", json.dumps({"code": code, "email": email}), ex=STEP_UP_TTL)
    r.delete(f"lab:agent:stepup_tries:{sid}")
    if email:
        r.rpush(f"lab:mailbox:{email}", json.dumps({"subject": "Confirm your Kestrel order", "code": code,
                                                    "ts": int(time.time() * 1000)}))
        r.expire(f"lab:mailbox:{email}", 3600)
    return {"sent_to": _mask(email), "digits": 6, "ttl_s": STEP_UP_TTL}


def _stepup_verify(ctx, answer):
    r, sid = ctx.redis, ctx.session.sid
    if r.incr(f"lab:agent:stepup_tries:{sid}") > STEP_UP_TRIES:
        return False, "too many attempts: ask for a new code"
    r.expire(f"lab:agent:stepup_tries:{sid}", STEP_UP_TTL)
    raw = r.get(f"lab:agent:stepup:{sid}")
    if not raw:
        return False, "no code was sent to this session, or it expired"
    if not hmac.compare_digest(str((answer or {}).get("code", "")).strip(), json.loads(raw)["code"]):
        return False, "that code is wrong"
    r.delete(f"lab:agent:stepup:{sid}")
    return True, ""


# --- routes ------------------------------------------------------------------------------------

@bp.route("/agent-policy")
def agent_policy_doc():
    """What agents may do here. Ungated: it is the first thing an agent should read."""
    level = current_app.config["LAB"].defense_level
    return jsonify({**_d("agent_policy").AGENT_POLICY, "level": level,
                    "identity": "HTTP Message Signatures (RFC 9421), Web Bot Auth profile; the Signature-Agent "
                                "origin must be one this store trusts",
                    "mandates": "POST /api/account/mandates from the account holder's own session; send the id "
                                "in the drop form's mandate field or the X-Agent-Mandate header"})


@bp.route("/api/account/mandates", methods=["GET", "POST"])
def mandates_api():
    user = current_user()
    if user is None:
        return api_error("unauthenticated", "Log in first.", 401)
    mandates = _d("mandates")
    if request.method == "GET":
        return jsonify(items=[mandates.public(m) for m in mandates.for_user(g.ctx.redis, user.id)])
    p = _d("principal").principal(g.ctx)
    if p["kind"] != "human":
        return api_error("agent_cannot_grant", f"Mandates are granted by account holders, not by agents ({p['kind']}).", 403)
    body = request.get_json(silent=True) or {}
    operator, sku = str(body.get("operator", "")).strip().lower(), str(body.get("sku", ""))
    if not operator or not Product.query.filter_by(sku=sku).first():
        return api_error("invalid", "operator and a valid sku are required.")
    m = mandates.grant(g.ctx.redis, user.id, operator, sku, body.get("ttl_min", 15))
    return jsonify(ok=True, mandate=mandates.public(m)), 201


def _markdown():
    """before_request, registered after the gate's: a Markdown catalogue for agents (level >= 1)."""
    ctx = getattr(g, "ctx", None)
    if ctx is None or ctx.level < 1 or request.method != "GET" or request.path != "/products":
        return None
    t0 = time.perf_counter()
    pol = _d("agent_policy")
    if not pol.wants_markdown(ctx.header("Accept"), _d("principal").principal(ctx)):
        return None
    from ..routes.pages import listing_query, paginate
    items, page, pages, _ = paginate(listing_query(request.args.get("q", "").strip(), request.args.get("category", ""),
                                                   request.args.get("sort", "featured")), request.args.get("page", 1, type=int))
    text, tokens = pol.markdown_catalog([p.to_dict() for p in items], page, pages)
    resp = Response(text, mimetype="text/markdown")
    resp.headers.update({"X-Markdown-Tokens": str(tokens), "Content-Signal": "search=yes, ai-input=yes, ai-train=no",
                         "Vary": "Accept, User-Agent"})
    g.gate_ms += (time.perf_counter() - t0) * 1000
    return resp


# --- after a purchase ---------------------------------------------------------------------------

def _after_buy(ctx, result, response):
    """The order is committed. Say who placed it, spend the mandate, count the unit against the device."""
    order = result["order"]
    p = _d("principal").principal(ctx)
    attribution = {"placed_by": p["kind"], "operator": p.get("operator")}
    mandate_id = ctx.attrs.get("mandate_ok")
    if mandate_id:
        attribution["mandate"] = mandate_id
        _d("mandates").consume(ctx.redis, mandate_id)
    order.extra = {**(order.extra or {}), **attribution}
    db.session.commit()
    gate = _d("checkout_gate")
    if ctx.notes.get("sku") == gate.PROTECTED_SKU:
        sess = _d("agent_session")
        key = f"{sess.DEVICE_PREFIX}{sess.device_key(ctx)}"
        ctx.redis.incr(key)
        ctx.redis.expire(key, 86400)
    return None


def init(app):
    start_mock()
    hooks.enricher(_enrich)
    hooks.telemetry.register("agent", lambda ctx, payload: _d("agent_session").record_telemetry(ctx, payload))
    hooks.challenges.register(STEP_UP, issue=lambda ctx: _stepup_issue(ctx), verify=lambda ctx, a: _stepup_verify(ctx, a),
                              render="agents/stepup.html", clearance_ttl=STEP_UP_TTL, uses=1)
    hooks.slot("body_end", "agents/collector.html")
    hooks.slot("form:drop", "agents/mandate_field.html")
    hooks.ungate("/agent-policy")
    hooks.on_action("drop_buy", _after_buy)
    hooks.on_reset(_reset_mock)
    app.register_blueprint(bp)
    app.before_request(_markdown)
