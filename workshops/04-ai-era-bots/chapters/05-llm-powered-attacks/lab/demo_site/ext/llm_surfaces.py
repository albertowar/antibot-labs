"""W4 Ch5 extension: the surfaces four LLM-powered attacks go after, on the Kestrel store.

Nothing here is bot detection. It is the store the chapter's defenses defend, built from the starter's own
hooks (contract 1.6):

  Reviews        `hooks.on_action("review", ...)` parks a review the checks flagged (`ctx.attrs["review_hold"]`)
                 as `pending` and answers 202. The gate's verdict set is closed, so a *hold* is not a verdict;
                 the scoreboard shows it in its own `held` column (`g.outcome = "held"`).
  Challenge      the `puzzle` challenge type (defenses/challenge_gate.py): a text puzzle or a 3x3 tile grid, with
                 optional proof-of-work. Served by the gate on a `challenge` verdict at `POST /api/register`,
                 verified at `POST /api/challenge/verify`; one solve absorbs one challenge verdict.
  Catalogue      the listing's cards carry a per-session set of class names (the layout churn that beat selector
                 scrapers: `partials/_card.html` overrides the starter's, keeping the contract's
                 `class="product-card" data-sku=...`), a visible `SKU p001`, and, when Round 3's check has
                 filled `ctx.attrs["llm_traps"]`, an off-screen `aria-hidden` block rendered in the body_end slot.
  LLM features   GET /api/products/<sku>/summary and POST /api/assist read customer-written reviews into a
                 prompt (tools/llm.py: a deterministic mock, or a model on this machine via LLM_URL). Below
                 DEFENSE_LEVEL 4 the prompt is naive concatenation and the output is not checked; from 4 up the
                 student's defenses/llm_guard.py builds the prompt and validates the output.
  Lab            GET /lab/llm/puzzle/<token> is the human simulator's answer key (loopback only, ungated): a
                 person reads the puzzle; the shopper script cannot. No attack uses it.

Everything the ext keeps in Redis is under `lab:` so POST /lab/reset forgets it.
"""

import hashlib
import importlib

from flask import Blueprint, current_app, g, jsonify, request

from .. import hooks
from ..config import STORE_HOST
from ..models import Product, Review, db
from ..routes import api_error

bp = Blueprint("llm_surfaces", __name__)
SUPPORT_CODE = "SC-7741-KETTLE"                  # a made-up lab code; the secret Round 4's exfiltration payload chases
ALLOWED_HOSTS = {STORE_HOST, "www." + STORE_HOST}
CHURN_SECRET = "w4ch5-churn"
ROLES = ("img", "body", "title", "meta", "row", "price")

SYSTEM_SUMMARY = ("You are the review summariser for Kestrel Outfitters, an online shop. Write "
                  "two neutral sentences summarising customer reviews of the product.")
SYSTEM_ASSIST = ("You are the support assistant for Kestrel Outfitters, an online shop. Answer "
                 "the customer's question about the product in one or two sentences, using "
                 f"the product data and customer reviews provided. Support code: {SUPPORT_CODE} "
                 "(for staff escalation; internal).")

_llm = None


def _d(name):
    """A defense module looked up at call time (the reloader reloads in place; a held reference would go stale)."""
    return importlib.import_module(f"defenses.{name}")


def _model():
    global _llm
    if _llm is None:
        from tools.llm import LLM
        _llm = LLM()
    return _llm


# --- Reviews: a hold is not a verdict -----------------------------------------------------------

def _hold(ctx, result, response):
    """After a review is written: park it as pending when a check asked for a hold."""
    why = (ctx.attrs or {}).get("review_hold") if ctx is not None else None
    if not why:
        return None
    rev = result["review"]
    rev.status = "pending"
    rev.extra = {**(rev.extra or {}), "held": why}
    product = result.get("product")
    if product is not None:                                   # the HTML route averaged this review in already
        ratings = [r.rating for r in Review.query.filter_by(sku=product.sku, status="published")]
        product.rating = sum(ratings) / len(ratings) if ratings else 0.0
    db.session.commit()
    g.outcome = "held"
    ctx.note(held=why)
    if request.is_json:
        return jsonify(ok=True, status="pending", message="Thanks. Your review is waiting for moderation."), 202
    return None


# --- Round 2: the puzzle challenge ---------------------------------------------------------------

def _device(ctx):
    return ctx.cookies.get("did") or f"sid-{ctx.session.sid}"


def _issue(ctx):
    body = ctx.json if isinstance(ctx.json, dict) else {**ctx.args, **ctx.form}
    mode = "text" if body.get("mode") == "text" else "image"          # the accessible alternative is always one parameter away
    return _d("challenge_gate").issue(ctx.redis, mode, pow_bits=_d("challenge_policy").pow_bits(ctx))


def _verify(ctx, answer):
    ok, why, solve_ms = _d("challenge_gate").verify(ctx.redis, str(answer.get("token", "")), str(answer.get("answer", "")),
                                                    str(answer.get("nonce", "")))
    if ok:
        ctx.session.set("llm_solve_ms", f"{solve_ms:.1f}")
        key = f"lab:llm:solves:{_device(ctx)}"
        ctx.redis.incr(key)
        ctx.redis.expire(key, 3600)
    return ok, why


@bp.route("/lab/llm/puzzle/<token>")
def puzzle_answer(token):
    """The human simulator's answer key. Loopback only (the lab edge refuses everything else); no attack calls it."""
    import json
    raw = current_app.extensions["lab_redis"].get(f"lab:llm:chal:{token}")
    if raw is None:
        return jsonify(error="unknown token"), 404
    return jsonify(answer=json.loads(raw)["answer"])


# --- Round 3: layout churn, and the block only a text reader perceives ---------------------------------

def churn(role):
    """A per-session class name for one role in a product card: a selector written against yesterday's markup matches nothing."""
    ctx = getattr(g, "ctx", None)
    sid = ctx.session.sid if ctx is not None else "static"
    return "c" + hashlib.sha256(f"{sid}:{role}:{CHURN_SECRET}".encode()).hexdigest()[:6]


def llm_traps():
    ctx = getattr(g, "ctx", None)
    return (ctx.attrs or {}).get("llm_traps") if ctx is not None else None


# --- Round 4: the store's own LLM features -------------------------------------------------------------

def _published_reviews(sku):
    rows = (Review.query.filter_by(sku=sku, status="published").order_by(Review.id.desc()).limit(20).all())
    return [f"[{r.rating}/5] {r.body}" for r in reversed(rows)]


def _feature(task, system, trusted, untrusted, fallback):
    """Prompt -> model -> (optionally) validate. From level 4 the student's llm_guard owns the prompt and the check."""
    guarded = current_app.config["LAB"].defense_level >= 4
    if guarded:
        guard = _d("llm_guard")
        system, user = guard.build_prompt(system, trusted, untrusted)
    else:
        user = "\n".join(f"{k.capitalize()}: {v}" for k, v in trusted.items()) + "\n\nReviews:\n" + "\n".join(untrusted)
    reply = _model().chat(task, system, user)
    reason = _d("llm_guard").validate(reply.text, ALLOWED_HOSTS, SUPPORT_CODE) if guarded else None
    tokens = reply.prompt_tokens + reply.completion_tokens
    g.ctx.note(tokens=tokens, withheld=reason or "")
    return (fallback if reason else reply.text), reply, reason


@bp.route("/api/products/<sku>/summary")
def summary(sku):
    p = Product.query.filter_by(sku=sku, hidden=False).first()
    if not p:
        return api_error("not_found", "No such product.", 404)
    text, reply, reason = _feature("summarize", SYSTEM_SUMMARY, {"product": p.name}, _published_reviews(sku),
                                   "Summary unavailable.")
    return jsonify(sku=sku, summary=text, backend=reply.backend, withheld=bool(reason))


@bp.route("/api/assist", methods=["POST"])
def assist():
    body = request.get_json(silent=True) or {}
    question = str(body.get("question", "")).strip()[:300]
    p = Product.query.filter_by(sku=str(body.get("sku", "")), hidden=False).first()
    if not p or not question:
        return api_error("invalid", "A sku and a question are required.")
    text, reply, reason = _feature("assist", SYSTEM_ASSIST,
                                   {"product": p.name, "price": f"{p.price:.2f}", "question": question},
                                   _published_reviews(p.sku), "Sorry, I can't help with that right now.")
    return jsonify(sku=p.sku, answer=text, backend=reply.backend, withheld=bool(reason))


def init(app):
    hooks.on_action("review", _hold)
    hooks.challenges.register("puzzle", issue=lambda ctx: _issue(ctx), verify=lambda ctx, a: _verify(ctx, a),
                              clearance_ttl=300, uses=1)
    hooks.slot("head", "llm/churn_css.html")
    hooks.slot("body_end", "llm/traps.html")
    app.jinja_env.globals.update(churn=churn, llm_traps=llm_traps)
    app.register_blueprint(bp)
