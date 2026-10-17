"""
W4 Ch9 extension: the capstone's store surface on the shared Kestrel chassis.

What this module adds (the decision logic lives in defenses/, wired by the ladder):

    crawl gate            before_request on content paths (L1, registered after the
                          gate so g.ctx exists): crawler identity × purpose ->
                          allow / charged / 402 / maze / block, with the ledger.
                          A Check cannot express a 402 or a maze page, so this is
                          the W4 Ch3 pattern, reading ctx.level itself.
    reply shaping         after_request (L4): defenses/oracle_guard.shape() on the
                          ext's own JSON replies and the crawl refusals. Below L4
                          they stay leaky on purpose (score + reasons: how you read
                          the model while you tune it; W4 Ch6's oracle lesson).
    telemetry             kind "capstone": demo_site/static/js/capstone.js posts the
                          fingerprint and input events; stored under lab:cap:* so
                          /lab/reset clears them; defenses/capstone.session_state
                          reads them for the W2-shadow stack and the signal row.
    challenges            pow / captcha_image / confirm_code as registered types
                          (defenses/challenges.py primitives; confirm_code emails
                          the account's mailbox, the starter /lab/mailbox reads it).
    policy surface        /llms.txt, /license.xml, /agent-policy, /appeal,
                          /.well-known/{governance,tdm-policy}.json, the reservation
                          lines on /robots.txt (hooks.robots) and the Content-Usage
                          headers on content replies.
    agent commerce        GET/POST /api/account/mandates (people grant mandates;
                          defenses/mandates.py holds them), markdown catalogue for
                          agents that ask (Accept: text/markdown).
    deception (L3)        decoy records, canary notes and hidden honeypot links on
                          the catalogue and product pages (defenses/deception_limits
                          decides WHO sees them); honeypot SKU fetches are blocked
                          and logged; /maze/<token> serves the tarpit.
    lab oracles           /lab/answer/<token> (the image-challenge answer for the
                          sighted simulator), /lab/canaries, /lab/cap/status
                          (ledger, maze bytes, rules, llm backend).
    seed + reset          hidden honeypot products, the persona and attacker-owned
                          accounts, operator keys (tools/make_keys.py) on init; the
                          rules/ and mandate state restored on POST /lab/reset.

Ground truth (X-Lab-Actor) is never read here; the scoreboard reads it from the
decision log, as everywhere else in the series.
"""

import hashlib
import json
import os
import random
import threading
import time

from flask import Blueprint, Response, current_app, g, jsonify, render_template_string, request

from defenses import capstone, challenges, content_heuristics, crawl_policy, crawler_registry
from defenses import crawl_governance, crawler_identity, deception_limits, injection_regex, llm_guard
from defenses import mandates, maze as maze_mod
from defenses import oracle_guard, policy_engine, rules as rules_mod
from defenses.decision import ALLOW, BLOCK, CHARGED, MAZE, PAYWALL
from demo_site import hooks

bp = Blueprint("capstone", __name__)

DROP_SKU = "lab-runner-9"
SUPPORT_CODE = "SC-7741-KETTLE"
CONTENT_PREFIXES = ("/catalog", "/products", "/product/", "/search", "/api/products", "/sitemap.xml", "/feed.xml")
SYSTEM_SUMMARY = ("You are the review summariser for Kestrel Outfitters, an online shop. Write two neutral "
                  "sentences summarising customer reviews of the product.")
SYSTEM_ASSIST = ("You are the support assistant for Kestrel Outfitters, an online shop. Answer the customer's "
                 "question about the product in one or two sentences, using the product data and customer "
                 f"reviews provided. Support code: {SUPPORT_CODE} (for staff escalation; internal).")
HONEYPOT_SKUS = ("hp-101", "hp-102", "hp-103")

_babbler = None
_inflight = threading.BoundedSemaphore(8)
_llm = None


def _level():
    return current_app.config["LAB"].defense_level


def _store():
    return current_app.extensions["lab_redis"]


def _secret():
    return current_app.config["LAB"].secret


def llm():
    global _llm
    if _llm is None:
        from tools.llm import LLM
        _llm = LLM()
    return _llm


def babbler():
    global _babbler
    if _babbler is None:
        from defenses.babble import Babbler
        from demo_site.models import Product
        _babbler = Babbler([p.blurb or p.name for p in Product.query.limit(120)])
    return _babbler


def is_content_path(path):
    return path == "/" or path.startswith(CONTENT_PREFIXES)


# --- telemetry: what capstone.js collects --------------------------------------------------------

def on_capstone_telemetry(ctx, payload):
    from defenses.fingerprint_coherence import fingerprint_hash
    page = str(payload.get("page", ""))[:100]
    fp = payload.get("fp") if isinstance(payload.get("fp"), dict) else {}
    events = payload.get("events") if isinstance(payload.get("events"), dict) else {}
    fph = fingerprint_hash(fp)
    r, sid = ctx.redis, ctx.session.sid
    pipe = r.pipeline()
    pipe.set(f"lab:cap:fp:{sid}", json.dumps(fp), ex=3600)
    pipe.set(f"lab:cap:fph:{sid}", fph, ex=3600)
    pipe.set(f"lab:cap:ev:{sid}:{page}", json.dumps(events), ex=3600)
    pipe.sadd(f"lab:cap:evpages:{sid}", page)
    pipe.expire(f"lab:cap:evpages:{sid}", 3600)
    pipe.execute()
    return {"fp_hash": fph}


# --- challenges ------------------------------------------------------------------------------------

def _issue(kind):
    def issue(ctx):
        return challenges.issue(ctx.redis, kind, ctx.session.sid)
    return issue


def _verify(kind):
    def verify(ctx, answer):
        ok, _kind, why = challenges.verify(ctx.redis, str(answer.get("token", "")), answer)
        return ok, why
    return verify


def _issue_confirm(ctx):
    """The step-up: a one-time code to the ACCOUNT's mailbox. A person answers it."""
    import secrets as _secrets
    code = f"{_secrets.randbelow(10 ** 6):06d}"
    email = (ctx.user.email if ctx.user else "").lower()
    ctx.redis.set(f"lab:cap:stepup:{ctx.session.sid}", code, ex=600)
    if email:
        ctx.redis.rpush(f"lab:mailbox:{email}", json.dumps(
            {"subject": "Confirm your Kestrel order", "code": code, "ts": time.time()}))
        ctx.redis.expire(f"lab:mailbox:{email}", 3600)
    return {"kind": "confirm_code", "non_visual": True,
            "instructions": f"a confirmation code was emailed to {email or 'your account'}"}


def _verify_confirm(ctx, answer):
    want = ctx.redis.get(f"lab:cap:stepup:{ctx.session.sid}")
    got = str(answer.get("code", "")).strip()
    if not want:
        return False, "no code is pending, or it expired"
    if got != want:
        return False, "wrong code"
    ctx.redis.delete(f"lab:cap:stepup:{ctx.session.sid}")
    return True, "confirmed by a person"


# --- the crawl gate (L1) ---------------------------------------------------------------------------

def _crawl_gate():
    ctx = getattr(g, "ctx", None)
    if ctx is None or request.method != "GET" or not is_content_path(request.path):
        return None
    ident = crawler_identity.verify(ctx)
    rules = crawl_policy.rules()
    rule = rules.get(ident.purpose) if ident.operator else None
    disallowed = crawl_policy.is_disallowed(rule, request.path) if ident.operator else False
    minute = int(time.time() // 60)
    key = f"lab:cap:pages:{ctx.ip}:{minute}"
    pages = int(ctx.redis.incr(key))
    ctx.redis.expire(key, 120)
    cctx = {"identity": ident, "rule": rule, "path": request.path, "disallowed": disallowed,
            "egress_kind": capstone.egress_kind(ctx), "pages_per_min": pages,
            "maze_tagged": maze_mod.tagged(ctx.redis, ctx.ip), "price": crawl_policy.price_usd(),
            "exact": ctx.header("crawler-exact-price"), "max": ctx.header("crawler-max-price")}
    # crawl_governance is a top-level defenses module; demo_site/gate.py's reloader hot-reloads
    # it in place when --catch-up installs the solution, so a plain call sees the fresh code.
    d = crawl_governance.evaluate(cctx)
    enforced = ctx.level >= 1
    g.cap_crawl = {"identity": ident, "decision": d, "enforced": enforced}
    ctx.note(crawl=d.action, crawl_reason=d.reason[:160],
             crawler=ident.operator or None, crawl_how=ident.how)
    if enforced and d.action == CHARGED:
        ctx.redis.incrbyfloat(f"lab:cap:ledger:{ident.operator}", d.charged)
        ctx.redis.incrbyfloat("lab:cap:ledger:total", d.charged)
    if not enforced or d.action in (ALLOW, CHARGED):
        return None
    if d.action == BLOCK:
        g.outcome = "blocked"
        return Response(f"403 Forbidden\n{d.reason}\n", 403, mimetype="text/plain")
    if d.action == PAYWALL:
        g.outcome = "paywalled"
        return Response("402 Payment Required\n", 402, {"crawler-price": f"USD {d.charged:.2f}"},
                        mimetype="text/plain")
    if d.action == MAZE:
        g.outcome = "mazed"
        return _maze_response(ctx.ip)
    return None


def _maze_response(ip, token=None):
    token = token or hashlib.sha256(f"{_secret()}:dark:{ip}".encode()).hexdigest()[:12]
    title, paragraphs, children = maze_mod.render(token, babbler(), _secret())
    links = "".join(f"<li><a href='{maze_mod.MAZE_PREFIX}{c}'>{title.split()[0]} {i}</a></li>"
                    for i, c in enumerate(children))
    body = "".join(f"<p>{x}</p>" for x in paragraphs) + f"<ul>{links}</ul>"
    doc = ("<!doctype html><html lang='en'><head><meta charset='utf-8'>"
           f"<title>{title}</title><meta name='robots' content='noindex, nofollow'></head>"
           f"<body><h1>{title}</h1>{body}</body></html>")
    _store().incrby("lab:cap:maze:bytes", len(doc))
    hdrs = {"X-Robots-Tag": "noindex, nofollow", "Cache-Control": "no-store"}
    if not _inflight.acquire(blocking=False):
        _store().incr("lab:cap:maze:capped")
        return Response(doc, 200, hdrs, mimetype="text/html")

    def drip():
        try:
            step = max(1, len(doc) // maze_mod.DRIP_CHUNKS)
            for i in range(0, len(doc), step):
                yield doc[i:i + step]
                time.sleep(maze_mod.DRIP_DELAY)
        finally:
            _inflight.release()
    return Response(drip(), 200, hdrs, mimetype="text/html")


def _honeypot_block():
    """Fetching a honeypot SKU: only a machine reader finds the link."""
    ctx = getattr(g, "ctx", None)
    if ctx is None or not request.path.startswith("/product/"):
        return None
    sku = request.path.rsplit("/", 1)[-1]
    if sku in HONEYPOT_SKUS:
        ctx.note(honeypot_sku=sku)
        g.outcome = "blocked"
        return Response("403 Forbidden\nfetched a honeypot SKU: only a machine reader finds it\n",
                        403, mimetype="text/plain")
    return None


def _markdown_catalog():
    """Agents that ask get the catalogue as Markdown (cheap tokens, no decoys)."""
    from defenses import agent_policy
    ctx = getattr(g, "ctx", None)
    if ctx is None or request.path not in ("/catalog", "/products") or request.method != "GET":
        return None
    principal = (ctx.attrs.get("cap_principal") or agent_policy.classify(capstone._Headers(ctx)))
    if not agent_policy.wants_markdown(capstone._Headers(ctx), principal):
        return None
    from demo_site.models import Product
    products = {p.sku: {"name": p.name, "price": p.price_cents / 100, "category": p.category,
                        "drop": p.is_drop}
                for p in Product.query.filter_by(hidden=False).order_by(Product.sku)}
    text, tokens = agent_policy.markdown_catalog(products)
    resp = Response(text, mimetype="text/markdown")
    resp.headers["X-Markdown-Tokens"] = str(tokens)
    resp.headers["Vary"] = "Accept, User-Agent"
    return resp


def _before():
    # Order matters: honeypot SKUs are a hard block; the crawl gate governs every content
    # carrier (the markdown catalogue is one, so it must not bypass the paywall — W4 Ch3's
    # "every carrier behind the same policy"); only an allowed GET reaches the markdown path.
    r = _honeypot_block()
    if r is not None:
        return r
    r = _crawl_gate()
    if r is not None:
        return r
    return _markdown_catalog()


# --- reply shaping: leaky below L4, the oracle guard at L4 (after_request) ------------------------

def _shape(response):
    ctx = getattr(g, "ctx", None)
    if ctx is None:
        return response
    if is_content_path(request.path) and getattr(g, "cap_crawl", None) is not None:
        for k, v in crawl_policy.response_headers(request.host_url.rstrip("/"), ctx.level).items():
            response.headers[k] = v
        d = g.cap_crawl["decision"]
        if d.action == CHARGED and g.cap_crawl["enforced"]:
            response.headers["crawler-charged"] = f"USD {d.charged:.2f}"
    # the decision oracle: the gate's JSON refusals carry score + reasons "for teaching"
    # below L4; the student's oracle guard decides what survives at L4
    # an appeal link rides on every refusal the store publishes an appeal path for: a block a
    # person cannot contest is an Article 22 problem (Chapter 8), and the audit checks for it.
    if response.status_code in (402, 403, 429) and policy_engine.load_policy().get("appeal_path"):
        response.headers["Link"] = (response.headers.get("Link", "")
                                     + (", " if response.headers.get("Link") else "")
                                     + '</appeal>; rel="help"')
    if response.is_json and response.status_code in (402, 403, 429) and g.decisions:
        worst = max(g.decisions, key=lambda d: d.score)
        body = response.get_json(silent=True)
        if isinstance(body, dict):
            decision = {"score": worst.score, "reasons": [s.detail or s.flag() for s in worst.signals][:6]}
            shaped = oracle_guard.shape(dict(body, outcome=body.get("error", {}).get("code", "block")),
                                        decision, ctx.level)
            new = jsonify(shaped)
            new.status_code = response.status_code
            for k, v in response.headers:
                if k.lower() not in ("content-length", "content-type"):
                    new.headers[k] = v
            return new
    return response


# --- traps on the catalogue and product pages (L3) --------------------------------------------------

def cap_traps(page):
    ctx = getattr(g, "ctx", None)
    traps = {"hidden_records": [], "canary_note": None, "decoy_paragraphs": [], "honeypot_links": []}
    if ctx is None or ctx.level < 3:
        return traps
    from demo_site.models import Product
    canary = "LOT-" + hashlib.sha256(f"canary:{ctx.session.sid}:{_secret()}".encode()).hexdigest()[:8].upper()
    ctx.redis.hset("lab:cap:canary", canary, ctx.session.sid)
    hps = [{"sku": p.sku, "name": p.name, "price": p.price_cents / 100}
           for p in Product.query.filter(Product.sku.in_(HONEYPOT_SKUS))]
    sess = capstone.session_state(ctx, page)
    a11y = any(bool((ev or {}).get("a11y_api")) for ev in (sess.get("pages") or {}).values())
    # would_block mirrors the old capstone's would_refuse(): the crawl gate would refuse this
    # client, OR the advisory W1+W2 baseline (which runs in shadow) scores it into the
    # challenge band. The baseline's points live in each decision's shadow signals, not its
    # enforced score, so read those — that is the "what would the earlier stack say" verdict.
    from defenses.policy import BANDS
    would_block = False
    c = getattr(g, "cap_crawl", None)
    if c and c["decision"].action not in (ALLOW, CHARGED):
        would_block = True
    shadow_score = sum(s.points for d in g.decisions for s in d.shadow)
    if shadow_score >= BANDS["challenge"]:
        would_block = True
    traps = deception_limits.decorate({
        "sid": ctx.session.sid, "canary": canary, "page": page, "honeypots": hps,
        "would_block": would_block, "identity": c["identity"] if c else None, "a11y": a11y})
    traps.setdefault("honeypot_links", [])
    if traps.get("hidden_records") or traps.get("canary_note") or traps.get("decoy_paragraphs"):
        ctx.note(decoy_served=True)
    rng = random.Random(f"{ctx.session.sid}:{page}")
    hp_all = list(HONEYPOT_SKUS)
    traps["honeypot_links"] = rng.sample(hp_all, min(2, len(hp_all)))
    return traps


TRAPS_TEMPLATE = """{% set traps = cap_traps(request.path) %}
{% if traps.hidden_records or traps.canary_note or traps.decoy_paragraphs %}
<div class="vh" aria-hidden="true" data-decoy="1" style="position:absolute;left:-10000px">
{% if traps.canary_note %}<p>{{ traps.canary_note }}</p>{% endif %}
{% for h in traps.hidden_records %}<div class="product-card" data-sku="{{ h.sku }}"><a href="/product/{{ h.sku }}">{{ h.name }}</a> · ${{ '%.2f'|format(h.price) }} · SKU {{ h.sku }}</div>{% endfor %}
{% for d in traps.decoy_paragraphs %}<p>{{ d }}</p>{% endfor %}
</div>{% endif %}
{% for hp in traps.honeypot_links %}<a class="hp" style="display:none" href="/product/{{ hp }}" tabindex="-1" aria-hidden="true">{{ hp }}</a>{% endfor %}
<script src="/static/js/capstone.js"></script>"""


# --- LLM features -----------------------------------------------------------------------------------

def _guard():
    if getattr(g, "ctx", None) and g.ctx.level >= 3:
        return llm_guard

    class Naive:
        AI_DISCLOSURE = None

        @staticmethod
        def ingest(text):
            return injection_regex.evaluate(text)

        @staticmethod
        def build_prompt(system, trusted, untrusted):
            user = "\n".join(f"{k.capitalize()}: {v}" for k, v in trusted.items())
            return system, user + "\n\nReviews:\n" + "\n".join(untrusted)

        @staticmethod
        def validate(output, allowed, secret):
            from defenses.decision import allow
            return allow("output not validated")
    return Naive


def _published_reviews(sku):
    from demo_site.models import Review
    return [f"[{r.rating}/5] {r.body}" for r in
            Review.query.filter_by(sku=sku, status="published").order_by(Review.created_at).all()]


def _llm_feature(task, system, trusted, untrusted, fallback):
    gd = _guard()
    system2, user = gd.build_prompt(system, trusted, untrusted)
    out = llm().chat(task, system2, user)
    verdict = gd.validate(out.text, {request.host}, SUPPORT_CODE)
    text = out.text if verdict.action == ALLOW else fallback
    if getattr(g, "ctx", None):
        g.ctx.note(llm_task=task, llm_outcome=verdict.action, llm_tokens=out.prompt_tokens + out.completion_tokens,
                   llm_backend=out.backend)
    return text, gd.AI_DISCLOSURE, out


@bp.get("/product/<sku>/summary")
def summary(sku):
    from demo_site.models import Product
    p = Product.query.filter_by(sku=sku, hidden=False).first()
    if p is None:
        return jsonify(outcome="error", message="no such product"), 404
    text, disclosure, out = _llm_feature("summarize", SYSTEM_SUMMARY, {"product": p.name},
                                         _published_reviews(sku), "Summary unavailable.")
    body = {"summary": text, "backend": out.backend}
    if disclosure:
        body["ai_disclosure"] = disclosure
    return jsonify(body)


@bp.post("/assist")
def assist():
    from demo_site.models import Product
    body = request.get_json(silent=True) or {}
    sku = body.get("sku")
    question = str(body.get("question", "")).strip()[:300]
    p = Product.query.filter_by(sku=sku, hidden=False).first()
    if p is None or not question:
        return jsonify(outcome="error", message="sku and question required"), 400
    text, disclosure, out = _llm_feature(
        "assist", SYSTEM_ASSIST,
        {"product": p.name, "price": f"{p.price_cents / 100:.2f}", "question": question},
        _published_reviews(sku), "Sorry, I can't help with that right now.")
    resp = {"answer": text, "backend": out.backend}
    if disclosure:
        resp["ai_disclosure"] = disclosure
    r = jsonify(resp)
    if disclosure:
        r.headers["X-AI-Disclosure"] = "automated-assistant"
    return r


# --- the policy surface -----------------------------------------------------------------------------

def _robots_lines():
    level = current_app.config["LAB"].defense_level
    lines = crawl_policy.robots_txt("", level).splitlines()
    # merge into the starter's base group: skip its own group opener and blanket Allow
    # (contract 1.7 dropped leading Allow lines; RFC 9309 allows by default)
    out = [ln for ln in lines
           if ln.strip() and not ln.startswith("#")
           and ln.strip() not in ("User-agent: *", "Allow: /")
           and not ln.startswith(("License:", "Sitemap:"))]
    if level >= 1:
        out.append(f"License: {request.url_root.rstrip('/')}/license.xml")
    return out


@bp.get("/license.xml")
def license_xml():
    if _level() < 1:
        return Response("404\n", 404, mimetype="text/plain")
    return Response(crawl_policy.rsl_xml(request.host_url.rstrip("/"), crawl_policy.price_usd()),
                    mimetype="application/rsl+xml")


@bp.get("/llms.txt")
def llms_txt():
    return Response("# Kestrel Outfitters\n\n> A 120-product demo shop used in the Antibot Workshop.\n\n"
                    "## Catalogue\n- [Listing](/catalog?page=1)\n- [JSON](/api/products?page=1)\n\n"
                    "## Policy\n- [robots.txt](/robots.txt)\n- [RSL licence](/license.xml)\n- [Agents](/agent-policy)\n",
                    mimetype="text/markdown")


@bp.get("/.well-known/tdm-policy.json")
def tdm_policy():
    return jsonify({"tdm-reservation": 1, "policy": "Text and data mining is reserved. Licensed training crawls "
                                                    "are priced in /license.xml (RSL)."})


@bp.get("/agent-policy")
def agent_policy_doc():
    from defenses import agent_policy
    pol = policy_engine.load_policy()
    return jsonify({**agent_policy.AGENT_POLICY, "level": _level(), "policy": pol.get("name"),
                    "declaration": pol.get("declaration"), "checkout_step_up": pol.get("checkout_step_up"),
                    "challenge_type": pol.get("challenge_type"),
                    "identity": "HTTP Message Signatures (RFC 9421), Web Bot Auth profile; "
                                "Signature-Agent must be a trusted operator",
                    "mandates": "POST /api/account/mandates from the account holder's own session; "
                                "pass the id at checkout (mandate field or X-Agent-Mandate)"})


@bp.get("/appeal")
def appeal():
    pol = policy_engine.load_policy()
    if not pol.get("appeal_path"):
        return jsonify(outcome="error", message="This store publishes no appeal path."), 404
    return jsonify({"contact": "appeals@kestrel.test", "human_review_within_hours": 24,
                    "reinstated_by_default_after_hours": 72,
                    "how": "Reply with the time of the block and the email on the account. A person reviews it.",
                    "ai_disclosure": "The first reply may come from an automated assistant; it will say so."})


@bp.get("/.well-known/governance.json")
def governance():
    pol = policy_engine.load_policy()
    logp = crawl_policy.logging_policy()
    engine = rules_mod.RuleEngine()
    return jsonify({
        "retention_days": int(pol.get("retention_days", logp.get("retention_days", 365))),
        "appeal_path": "/appeal" if pol.get("appeal_path") else None,
        "terms": crawl_policy.terms() | {"agents_clause": pol.get("terms", {}).get("agents_clause")},
        "challenge_type": pol.get("challenge_type"), "checkout_step_up": pol.get("checkout_step_up"),
        "ai_features": ["review summariser", "support assistant"], "llm_backend": llm().backend,
        "policy": pol.get("name"), "rules": engine.describe(),
        "deception": "decoy content only for traffic the policy would otherwise refuse; never for crawlers "
                     "honouring the reservation or for sessions using the accessibility API",
        "level": _level(),
    })


@bp.get("/maze/<token>")
def maze_page(token):
    ctx = getattr(g, "ctx", None)
    if _level() < 1 or len(token) != 12 or any(c not in "0123456789abcdef" for c in token):
        return Response("404\n", 404, mimetype="text/plain")
    ip = ctx.ip if ctx else request.remote_addr
    n = maze_mod.record_hit(_store(), ip)
    if ctx:
        ctx.note(maze_page=n)
        g.outcome = "mazed"
    return _maze_response(ip, token=token)


# --- mandates ---------------------------------------------------------------------------------------

@bp.get("/api/account/mandates")
def list_mandates():
    ctx = g.ctx
    if ctx.user is None:
        return jsonify(outcome="error", message="Log in first."), 401
    return jsonify([mandates.as_json(m) for m in mandates.for_user(ctx.user.id)])


@bp.post("/api/account/mandates")
def grant_mandate():
    """The account holder authorises an agent operator to buy one thing, once, soon.
    People grant mandates; an agent cannot grant itself one."""
    from defenses import agent_policy
    from demo_site.models import Product
    ctx = g.ctx
    if ctx.user is None:
        return jsonify(outcome="error", message="Log in first."), 401
    principal, _identity = capstone.principal_identity(ctx)
    if principal["kind"] != "human":
        ctx.note(mandate="refused_agent")
        return jsonify(outcome="block",
                       message=f"An agent cannot grant itself a mandate ({principal['kind']})."), 403
    body = request.get_json(silent=True) or {}
    operator = str(body.get("operator", ""))[:120].strip().lower()
    sku = body.get("sku")
    ttl = max(1, min(int(body.get("ttl_min", 15) or 15), 60))
    if not operator or Product.query.filter_by(sku=sku, hidden=False).first() is None:
        return jsonify(outcome="error", message="operator and a valid sku are required."), 400
    m = mandates.grant(ctx.user.id, operator, sku, ttl)
    ctx.note(mandate="granted")
    return jsonify(outcome="allow", message="Mandate granted.", mandate=mandates.as_json(m))


# --- lab oracles ------------------------------------------------------------------------------------

@bp.get("/lab/answer/<token>")
def lab_answer(token):
    return jsonify({"answer": challenges.answer_for(_store(), token)})


@bp.get("/lab/canaries")
def lab_canaries():
    return jsonify(_store().hgetall("lab:cap:canary"))


@bp.post("/lab/cap/purge")
def cap_purge():
    """Retention: delete decision rows older than the published retention_days (?dry_run=1 counts).
    The governance record claims a retention limit; the audit confirms the store enforces it."""
    from datetime import timedelta
    from demo_site.models import Decision, db, utcnow
    days = int(policy_engine.load_policy().get("retention_days", 365))
    cutoff = utcnow() - timedelta(days=days)
    q = Decision.query.filter(Decision.ts < cutoff)
    n = q.count()
    if request.args.get("dry_run") != "1":
        q.delete()
        db.session.commit()
    return jsonify(ok=True, retention_days=days, cutoff=cutoff.isoformat(timespec="seconds"),
                   would_delete=n, deleted=0 if request.args.get("dry_run") == "1" else n)


@bp.get("/lab/cap/status")
def cap_status():
    r = _store()
    ledger = {k.split(":")[-1]: round(float(r.get(k) or 0), 2) for k in r.scan_iter("lab:cap:ledger:*")}
    engine = rules_mod.RuleEngine()
    return jsonify(level=_level(), ledger=ledger, maze_bytes=int(r.get("lab:cap:maze:bytes") or 0),
                   llm_backend=llm().backend, policy=policy_engine.load_policy().get("name"),
                   rules=engine.describe(), store="capstone")


# --- seed + reset -----------------------------------------------------------------------------------

def _seed_extras(app):
    """Honeypot SKUs (hidden) + the persona and attacker accounts, idempotently."""
    import sys
    sys.path.insert(0, current_app.config["LAB"].__class__.__module__ and "")  # no-op; tools on path below
    from demo_site.models import Order, Product, User, db, utcnow
    from demo_site.seed import set_password
    from datetime import timedelta
    import tools.personas as personas
    changed = False
    for i, sku in enumerate(HONEYPOT_SKUS):
        if Product.query.filter_by(sku=sku).first() is None:
            db.session.add(Product(sku=sku, name=f"Vault Sample {100 + i + 1}", category="packs",
                                   price_cents=129900 + i * 100, blurb="Archive item. Not for sale.",
                                   sizes=[], stock=0, rating=0.0, hidden=True))
            changed = True
    # The persona and attacker-owned accounts are test fixtures for the legit mix and the
    # farm, not part of the store's seed, so --smoke (LAB_SMOKE=1) checks the bare 301 users.
    # They carry backdated created_at (aged accounts), which is what Round 2's governance
    # trusts and the farm's fresh accounts lack — so they must be DB-seeded, not registered.
    if os.environ.get("LAB_SMOKE"):
        if changed:
            db.session.commit()
        return
    for rec in personas.legit_users() + personas.owner_accounts():
        if rec.get("register"):
            continue                      # the first-timer registers during the run
        if User.query.filter_by(email=rec["email"]).first() is None:
            u = User(email=rec["email"], name=rec["email"].split("@")[0][:40],
                     created_at=utcnow() - timedelta(days=rec["age_days"]))
            set_password(u, rec["password"], app.config["LAB"].hash_iters)
            db.session.add(u)
            db.session.flush()
            # Order numbers key off the email, not the auto-assigned id (which shifts when a
            # state reset re-seeds the base users), and each insert is guarded, so re-seeding
            # over a half-cleared table never collides on orders.number.
            tag = hashlib.sha256(rec["email"].encode()).hexdigest()[:8].upper()
            for n in range(rec.get("prior_orders", 0)):
                num = f"K9{tag}{n:02d}"
                if Order.query.filter_by(number=num).first() is None:
                    db.session.add(Order(number=num, user_id=u.id, email=u.email,
                                         total_cents=4900, status="paid", session_id=None,
                                         created_at=utcnow() - timedelta(days=max(1, rec["age_days"] - 7 * n))))
            changed = True
    if changed:
        db.session.commit()


def _reset(app):
    import os
    mandates.clear()
    lab = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    with open(os.path.join(lab, "rules", "active.json"), "w") as fh:
        json.dump({"version": 0, "rules": []}, fh, indent=2)
        fh.write("\n")
    for rel in ("rules/pending.json", "rules/audit.jsonl", "rules/trusted_operators.json"):
        path = os.path.join(lab, rel)
        if os.path.exists(path):
            os.remove(path)
    with app.app_context():
        _seed_extras(app)


def _on_drop_buy(ctx, result, response):
    """A completed drop purchase counts against the device (fingerprint) cap: the fleet of
    fresh accounts on one machine shares a fingerprint, so the second buy on that device is
    blocked (defenses/capstone._units reads lab:cap:dev:fp:<fp_hash>). Keyed on the fingerprint,
    not a cookie, because a cookie minted on the first response cannot stand for a trusted device."""
    if ctx is None or result.get("order") is None:
        return None
    fph = ctx.redis.get(f"lab:cap:fph:{ctx.session.sid}") or "none"
    ctx.redis.incr(f"lab:cap:dev:fp:{fph}")
    mid = (ctx.attrs.get("cap_extra") or {}).get("mandate_ok")
    if mid:
        mandates.spend(mid)          # a mandate is one purchase: mark it used so it cannot be replayed
    return None


def init(app):
    import os
    import sys
    lab = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    if lab not in sys.path:
        sys.path.insert(0, lab)
    from tools import make_keys
    make_keys.make()
    with app.app_context():
        _seed_extras(app)
    hooks.telemetry.register("capstone", on_capstone_telemetry)
    hooks.challenges.register("pow", issue=_issue("pow"), verify=_verify("pow"), uses=1)
    hooks.challenges.register("captcha_image", issue=_issue("captcha_image"),
                              verify=_verify("captcha_image"), uses=1)
    hooks.challenges.register("confirm_code", issue=lambda ctx: _issue_confirm(ctx),
                              verify=lambda ctx, a: _verify_confirm(ctx, a), uses=1)
    hooks.robots(_robots_lines)
    hooks.slot("body_end", "capstone/traps.html")
    hooks.stopped_outcome("mazed", "paywalled")
    hooks.on_action("drop_buy", _on_drop_buy)
    hooks.on_reset(_reset)
    app.before_request(_before)            # runs AFTER the gate's own before_request
    app.after_request(_shape)              # runs BEFORE the gate's stamp (reverse order)
    app.add_template_global(cap_traps, "cap_traps")
    app.register_blueprint(bp)
