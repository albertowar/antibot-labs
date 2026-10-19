"""
The gate: glue between Flask and the defenses.

before_request   build the Ctx, run enrichers, run the ladder, apply the policy's
                 answer (serve / challenge / block / 429 / deceive)
after_request    stamp X-Lab-* headers and Server-Timing, write the decision log

Chapters never edit this file. They add checks (defenses/), ext modules
(demo_site/ext/) and tune policy.py.
"""

import secrets
import time

from flask import g, jsonify, make_response, redirect, render_template, request

from defenses import pipeline, policy, reloader
from defenses.context import Ctx, EdgeInfo, Session, UserAgent

from . import hooks

SESSION_COOKIE = "sid"
DEVICE_COOKIE = "did"


def _session(redis):
    sid = request.cookies.get(SESSION_COOKIE)
    new = False
    if not sid or not redis.exists(f"lab:s:{sid}"):
        sid, new = secrets.token_urlsafe(24), True
    s = Session(redis, sid, new=new)
    if new:
        s.set("created_at", f"{time.time()}")
        s.set("created_ip", request.environ.get("lab.edge", {}).get("ip", request.remote_addr))
        s.set("created_asn", request.environ.get("lab.edge", {}).get("asn", 0))
    return s


def _edge_info():
    e = request.environ.get("lab.edge") or {"ip": request.remote_addr}
    ja4 = request.environ.get("lab.ja4_measured", "")
    src = "measured" if ja4 else ""
    if not ja4 and request.environ.get("lab.ja4_claimed"):
        ja4, src = request.environ["lab.ja4_claimed"], "claimed"
    return EdgeInfo(ip=e.get("ip", ""), asn=e.get("asn", 0), org=e.get("org", ""), country=e.get("country", ""),
                    pool=e.get("pool", ""), ja4=ja4, ja4_source=src, h2=request.environ.get("lab.h2", ""),
                    xff_claimed=request.environ.get("lab.xff_claimed", ""))


def build_ctx(app):
    redis = app.extensions["lab_redis"]
    s = _session(redis)
    user = None
    if s.user_id:
        from .models import User
        user = User.query.get(s.user_id)
    headers = [(k, v) for k, v in request.headers if not k.lower().startswith("x-lab-")]
    body = request.get_json(silent=True) if request.is_json else None

    def _cleared(ctype=None):
        names = [ctype] if ctype else hooks.challenges.names()
        return any(bool(redis.get(f"lab:s:{s.sid}:clear:{t}")) for t in names)

    ctx = Ctx(method=request.method, path=request.path, host=request.host, args=request.args.to_dict(),
              form=request.form.to_dict(), json=body, cookies=request.cookies.to_dict(), headers=headers,
              ua=UserAgent.parse(request.headers.get("User-Agent", "")), edge=_edge_info(), session=s,
              user=user, redis=redis, level=app.config["LAB"].defense_level,
              route=request.endpoint or "", view_args=dict(request.view_args or {}),
              query_string=request.query_string.decode("utf-8", "replace"), scheme=request.scheme,
              resumed=_cleared() if hooks.challenges.types else False, _clearance=_cleared,
              _telemetry=lambda kind: _read_telemetry(redis, s.sid, kind))
    return ctx


def _read_telemetry(redis, sid, kind):
    import json
    raw = redis.get(f"lab:s:{sid}:telemetry:{kind}")
    return json.loads(raw) if raw else None


def has_clearance(ctx, ctype):
    return bool(ctx.session.get(f"cleared:{ctype}"))


def _clear_key(ctx, ctype):
    return f"lab:s:{ctx.session.sid}:clear:{ctype}"


def grant_clearance(ctx, ctype, ttl=None, uses=None):
    """Mark the session as having passed `ctype`. Lifetime: `ttl` seconds (default: the type's
    clearance_ttl, else policy.CLEARANCE_TTL). `uses`: how many challenge verdicts it may absorb
    before it is spent (default: the type's `uses`, else unlimited)."""
    spec = hooks.challenges.get(ctype) or {}
    ttl = ttl or spec.get("clearance_ttl") or policy.CLEARANCE_TTL
    uses = uses if uses is not None else spec.get("uses")
    ctx.session.set(f"cleared:{ctype}", f"{time.time()}")
    # Clearance lives in a separate expiring key, so the session hash itself survives.
    ctx.redis.set(_clear_key(ctx, ctype), "inf" if uses is None else str(int(uses)), ex=int(ttl))


def revoke_clearance(ctx, ctype):
    """Take a clearance away (a check decided the pass is stolen, shared or over budget)."""
    ctx.redis.delete(_clear_key(ctx, ctype))
    ctx.session.delete(f"cleared:{ctype}")


def clearance_valid(ctx, ctype):
    return bool(ctx.redis.get(_clear_key(ctx, ctype)))


def spend_clearance(ctx, ctype):
    """A clearance absorbed one challenge verdict. Counted clearances run out. The downgrade
    rule calls this; a policy that allows after a solve itself can call it to spend the pass."""
    if ctx.redis.get(_clear_key(ctx, ctype)) in (None, "inf"):
        return
    left = ctx.redis.decr(_clear_key(ctx, ctype))
    if left <= 0:
        revoke_clearance(ctx, ctype)


_spend_clearance = spend_clearance      # pre-1.7 name, kept for existing labs


def run_phase(phase, ctx=None):
    """Run the ladder for a phase (routes call this for action:* phases). Returns a Decision."""
    from flask import current_app
    cfg = current_app.config["LAB"]
    ctx = ctx or g.ctx
    # LAB_SMOKE=1 (tools/verify.py --smoke) tests the bare store: no ladder at any level,
    # so a lab may wire a permanent baseline at LADDER[0] and smoke still passes.
    ladder = {} if cfg.lab_smoke else (reloader.ladder() if cfg.lab_reload else _static_ladder())
    t0 = time.perf_counter()
    d = pipeline.run(phase, ctx, ladder, cfg.defense_level, cfg.lab_shadow, cfg.lab_shadow_checks)
    # The downgrade rule: a session holding a valid clearance for the challenge type a verdict
    # asks for is served (as "monitor") instead of challenged again. A check that wants to
    # re-challenge a cleared session must revoke_clearance() first (W1 Ch7's pass budget does).
    if d.action == "challenge" and d.challenge and clearance_valid(ctx, d.challenge):
        d.action, ctx.notes["cleared"] = "monitor", d.challenge
        spend_clearance(ctx, d.challenge)
    if hasattr(g, "gate_ms"):
        g.gate_ms += (time.perf_counter() - t0) * 1000
    g.decisions.append(d)
    return d


def _static_ladder():
    from defenses import ladder
    return ladder.LADDER


def wants_json():
    """Should this request be answered in JSON (API path, JSON body, or no HTML Accept)?"""
    return request.path.startswith("/api/") or request.is_json or \
        "text/html" not in request.headers.get("Accept", "text/html")


def respond(d, ctx):
    """Turn a Decision into the HTTP answer the client gets, or None to let the route run."""
    as_json = wants_json()
    if d.action in ("allow", "monitor"):
        return None
    if d.action == "deceive":
        g.deceive = True            # the route serves a fake success (trap chapters)
        return None
    if d.action == "rate_limit":
        retry = d.retry_after or 5
        if as_json:
            r = jsonify(error={"code": "rate_limited", "message": "Too many requests."})
        else:
            r = make_response(render_template("blocked.html", reason="rate_limited", decision=d), 429)
        r.status_code = 429
        r.headers["Retry-After"] = str(retry)
        g.outcome = "rate_limited"
        return r
    if d.action == "challenge":
        ctype = hooks.challenges.get(d.challenge) if d.challenge else None
        if ctype is None:           # nothing registered: enforced as a block, and visibly so
            g.outcome = "blocked"
            if as_json:
                return jsonify(error={"code": "challenge_unavailable", "message": "Access denied."}), 403
            return render_template("blocked.html", reason="challenge_unavailable", decision=d), 403
        g.outcome = "challenged"
        payload = ctype["issue"](ctx)
        if as_json:
            return jsonify(error={"code": "challenge_required", "challenge": d.challenge, "payload": payload}), 403
        tpl = ctype["render"] or "challenge.html"
        # A challenge met on a form POST must not lose the form: the interstitial carries the
        # submitted fields (echoed back to the client that sent them, nobody else) in a hidden
        # resubmit form with a fresh csrf, so one click replays the POST after the solve.
        replay = None
        if request.method == "POST" and request.form:
            replay = {k: v for k, v in request.form.items() if k != "csrf"}
            csrf = ctx.session.get("csrf")
            if not csrf:
                csrf = secrets.token_urlsafe(16)
                ctx.session.set("csrf", csrf)
        return render_template(tpl, challenge=d.challenge, payload=payload, decision=d, next=request.full_path,
                               replay=replay, replay_csrf=ctx.session.get("csrf", "") if replay else ""), 403
    g.outcome = "blocked"
    if as_json:
        return jsonify(error={"code": "blocked", "message": "Access denied."}), 403
    return render_template("blocked.html", reason="blocked", decision=d), 403


def install(app):
    @app.before_request
    def _gate():
        g.t0 = time.perf_counter()
        g.gate_ms = 0.0
        g.decisions, g.outcome, g.deceive = [], None, False
        mode = hooks.ungate_mode(request.path)
        if mode == "skip":
            g.ctx = None
            return None
        t_ctx = time.perf_counter()
        ctx = build_ctx(app)
        g.ctx = ctx
        for fn in hooks.ENRICHERS:
            try:
                fn(ctx)
            except Exception as e:
                ctx.note(enricher_error=repr(e))
        g.gate_ms += (time.perf_counter() - t_ctx) * 1000      # Ctx build + enrichers count as gate cost
        if mode == "session":                                  # hooks.ungate(..., session=True):
            return None                                        # Ctx, cookie and a log row — no ladder
        d = run_phase("request", ctx)
        if d.action == "challenge" and request.path in ("/api/challenge", "/api/challenge/verify"):
            # A client in the challenge band must still be able to fetch and deliver the answer:
            # the two challenge endpoints are exempt from the challenge band (a block or a rate
            # limit still applies), or a VPN user scoring 40+ on every request could never solve.
            d.action = "monitor"
            ctx.note(challenge_exempt=1)
        return respond(d, ctx)

    @app.after_request
    def _stamp(response):
        ctx = getattr(g, "ctx", None)
        if hooks.RESPONSE_HOOKS:
            info = hooks.ResponseInfo(ctx=ctx, path=request.path, method=request.method,
                                      status=response.status_code, response=response,
                                      edge=request.environ.get("lab.edge") or {"ip": request.remote_addr},
                                      gated=ctx is not None)
            t_hooks = time.perf_counter()
            for fn in hooks.RESPONSE_HOOKS:
                try:
                    fn(info)
                except Exception as e:                   # a broken hook must never take the store down
                    if ctx is not None:
                        ctx.note(response_hook_error=repr(e))
            if ctx is not None and hasattr(g, "gate_ms"):
                g.gate_ms += (time.perf_counter() - t_hooks) * 1000   # observing is defender cost too
        if ctx is None:
            return response
        cfg = app.config["LAB"]
        if ctx.session.new or SESSION_COOKIE not in request.cookies:
            response.set_cookie(SESSION_COOKIE, ctx.session.sid, httponly=True, samesite="Lax", max_age=7 * 24 * 3600)
        if DEVICE_COOKIE not in request.cookies:
            response.set_cookie(DEVICE_COOKIE, secrets.token_urlsafe(16), httponly=False, samesite="Lax",
                                max_age=400 * 24 * 3600)
        decisions = getattr(g, "decisions", [])
        final = decisions[-1] if decisions else pipeline.Decision()
        # Most severe decision, score as the tie-break: a zero-score 429 outranks a
        # high-score monitor (contract 1.7; checkpoints that want the HTTP result read `outcome`).
        worst = max(decisions, key=lambda d: (pipeline.SEVERITY.get(d.action, 0), d.score)) if decisions else final
        total_ms = (time.perf_counter() - g.t0) * 1000
        ms = getattr(g, "gate_ms", total_ms)          # defender cost: Ctx build + enrichers + every ladder pass
        outcome = g.outcome or ("deceived" if g.deceive else ("purchased" if getattr(g, "purchased", False) else "served"))
        if response.status_code >= 500:
            outcome = "error"
        elif response.status_code == 404 and outcome == "served":
            outcome = "not_found"
        signals = sorted({f for d in decisions for f in d.flags()})
        shadow = sorted({f for d in decisions for f in d.shadow_flags()})
        if cfg.lab_headers:
            response.headers["X-Lab-Verdict"] = worst.action
            response.headers["X-Lab-Score"] = str(worst.score)
            response.headers["X-Lab-Signals"] = ",".join(signals)
            response.headers["X-Lab-Level"] = str(cfg.defense_level)
            if shadow:
                response.headers["X-Lab-Shadow"] = ",".join(shadow)
            # gate = defender cost only; app = the whole request (route included); then one entry per check
            timing = [f"gate;dur={ms:.2f}", f"app;dur={total_ms:.1f}"] + [f"{n};dur={t:.2f}" for d in decisions for n, t in d.checks]
            response.headers["Server-Timing"] = ", ".join(timing)
        response.headers.setdefault("Cache-Control", "no-store")
        log = app.extensions.get("decision_log")
        if log is not None:
            log.write({"sid": ctx.session.sid, "user_id": ctx.session.user_id,
                       "actor": request.environ.get("lab.actor", "you"),
                       "phase": ctx.phase or "request",
                       "method": request.method, "path": request.path, "ip": ctx.edge.ip, "level": cfg.defense_level,
                       "score": worst.score, "action": worst.action, "enforced": outcome, "outcome": outcome,
                       "status": response.status_code, "signals": ",".join(signals), "shadow": ",".join(shadow),
                       "ms": ms, "extra": dict(ctx.notes, total_ms=round(total_ms, 2),
                                               checks=[n for d in decisions for n, _ in d.checks])})
        return response
