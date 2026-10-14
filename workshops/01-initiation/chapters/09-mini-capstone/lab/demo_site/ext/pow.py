"""
Chapter 7 feature module: the proof-of-work challenge and everything the page needs to run it.

    hooks.challenges.register("pow", ...)   GET /api/challenge?type=pow, POST /api/challenge/verify,
                                            and the 403 interstitial the gate serves
    hooks.slot("body_end", ...)             pow.js (the solver) on every page; no JS, no pass
    hooks.telemetry.register("pow_bench")   the benchmark page reports its MH/s here
    /lab/pow/bench, /lab/pow/check          the two Round 0 / Round 4 lab pages (not gated)

What the page sees, step by step: the gate answers a protected page with a 403 interstitial;
pow.js solves the payload in Web Workers, POSTs the answer to /api/challenge/verify, and
reloads the page it came from. Which scheme (naive, signed, single-use) and which difficulty
is decided in defenses/pow_challenge.py and defenses/pow_adaptive.py, not here.
"""

from flask import Blueprint, current_app, jsonify, render_template

from defenses import pow_adaptive, pow_challenge, pow_gate
from defenses.pow_core import hashes_at_percentile

from .. import gate, hooks


def _bench(ctx, body):
    """pow_bench telemetry: {"kind": "pow_bench", "workers": 4, "mhs": 2.3}."""
    rate = float(body.get("mhs", 0)) * 1e6
    if rate <= 0:
        return None
    return {"p50_s": round(hashes_at_percentile(16, .5) / rate, 3), "p95_s": round(hashes_at_percentile(16, .95) / rate, 3)}


def init(app):
    # Wrappers, not the functions themselves: defenses/* is hot-reloaded and a registered
    # reference would keep running the old code after you edit it.
    hooks.challenges.register("pow", issue=lambda ctx: pow_challenge.issue(ctx),
                              verify=lambda ctx, answer: pow_challenge.verify(ctx, answer),
                              render="pow/interstitial.html")
    hooks.slot("body_end", "pow/solver.html")
    hooks.telemetry.register("pow_bench", _bench)

    bp = Blueprint("pow", __name__, url_prefix="/lab/pow")      # /lab/ is already ungated

    @bp.route("/bench")
    def bench():
        return render_template("pow/bench.html")

    @bp.route("/check")
    def check():
        """What the server sees, and what you would pay now."""
        ctx = gate.build_ctx(current_app)
        level = ctx.level
        rate = None
        if level >= 4:
            from defenses.store import Counters
            rate = Counters(ctx.redis, "lab:pow").count("rate", pow_adaptive.rate_key(ctx.ip), 60)
        return jsonify(level=level, client_ip=ctx.ip, rate_last_60s=rate,
                       difficulty_now=pow_adaptive.difficulty_for(rate or 0) if level >= 4 else (16 if level >= 1 else None),
                       has_pass=pow_gate.has_pass(ctx))

    app.register_blueprint(bp)
