"""
Chapter 2 extension: the JavaScript challenge.

What it adds (no starter file is edited):

    hooks.challenges "js"   GET /api/challenge?type=js, POST /api/challenge/verify, and the 403
                            interstitial the gate serves (js/interstitial.html): it embeds the
                            payload, loads the challenge script, posts the answer, reloads
    /jsc/l2.js              Round 2's one readable challenge script (variants.L2_CHAIN)
    static/js/variants/     Round 3+'s obfuscated variants, built by tools/build_variants.py
    /lab/jsc/check          the level, this session's pass, the pool, the budget (debug, never gated)

Which scheme runs at which level is in defenses/js_challenge.py; who must solve is in
defenses/js_gate.py. They are registered through lambdas because defenses/ is hot-reloaded.
"""

from flask import Blueprint, Response, current_app, jsonify

from demo_site import hooks


def _defenses():
    from defenses import clearance, env_integrity, js_challenge, js_gate, variants
    return clearance, env_integrity, js_challenge, js_gate, variants


def init(app):
    hooks.challenges.register("js", issue=lambda ctx: _defenses()[2].issue(ctx),
                              verify=lambda ctx, answer: _defenses()[2].verify(ctx, answer),
                              render="js/interstitial.html", clearance_ttl=1800)

    bp = Blueprint("jsc", __name__)

    @bp.route("/jsc/l2.js")
    def l2_script():
        variants = _defenses()[4]
        return Response(variants.render(variants.L2_CHAIN, variants.L2_PROBE), mimetype="application/javascript")

    @bp.route("/lab/jsc/check")
    def check():
        """Debug: the level, this session's pass and what the gate would do (never gated)."""
        from demo_site import gate
        clearance, env_integrity, js_challenge, js_gate, _ = _defenses()
        ctx = gate.build_ctx(current_app)
        level = current_app.config["LAB"].defense_level
        granted = ctx.session.get("cleared:js")
        used = ctx.redis.get(f"lab:jsc:budget:{ctx.session.sid}:{granted}") if granted else None
        return jsonify(level=level, sid=ctx.session.sid[:8],
                       cookie_pass=bool(ctx.cookies.get("js_ok")) if level == 1 else None,
                       clearance=bool(ctx.redis.get(js_gate.CLEAR_KEY.format(sid=ctx.session.sid))),
                       budget_used=int(used) if used else None, budget=clearance.BUDGET if level >= 5 else None,
                       variant_pool=len(js_challenge.pool()),
                       max_solve_ms=env_integrity.MAX_SOLVE_MS if level >= 4 else None,
                       naive_engine_check=env_integrity.NAIVE_ENGINE_CHECK if level >= 4 else None)

    app.register_blueprint(bp)
