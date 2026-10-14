"""
Capstone feature module: the login side of Round 4. No starter file is edited, and nothing here decides
anything (token_binding.py and login_risk.py decide).

    GET  /api/login/challenge   the proof-of-work challenge for a login token, bound to the fingerprint the
                                sensor reported for this session (refused with 409 when there is no report:
                                a client that never ran the page's JavaScript cannot even ask)
    POST /api/login/token       {nonce, counter} -> {token}
    form:login slot             login9.js: on submit, the page runs the flow above and puts the token in the
                                form, so a real customer never notices

The token is asked for at every level (the page always fetches one); only DEFENSE_LEVEL >= 5 refuses a login
without it. Ext modules are not hot-reloaded: restart the store after editing this file.
"""

from flask import Blueprint, g, jsonify, request

from defenses import token_binding
from demo_site import hooks

bp = Blueprint("login9", __name__, url_prefix="/api/login")


def _fp_hash():
    from defenses import sensor
    return token_binding.fingerprint_hash(sensor.report(g.ctx))


@bp.route("/challenge")
def challenge():
    fp = _fp_hash()
    if not fp:
        return jsonify(error={"code": "no_fingerprint", "message": "No sensor report for this session."}), 409
    return jsonify(token_binding.issue(g.ctx.redis, g.ctx.session.sid, fp))


@bp.route("/token", methods=["POST"])
def token():
    body = request.get_json(silent=True) or {}
    t = token_binding.redeem(g.ctx.redis, g.ctx.session.sid, _fp_hash(), str(body.get("nonce", "")), body.get("counter"))
    if t is None:
        return jsonify(error={"code": "bad_proof", "message": "Wrong proof, expired nonce, or no fingerprint."}), 403
    return jsonify(token=t)


def init(app):
    app.register_blueprint(bp)
    hooks.slot("form:login", "login9/token_field.html")
