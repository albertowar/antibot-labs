"""
Fake successes for a `deceive` verdict (contract 1.7).

gate.respond() sets g.deceive and lets the route run; guard() asks this module first.
Each fake here is indistinguishable from the real answer for that action, writes no
row, and leaves a note in the decision log. Two actions stay in their routes, which
hold the context a plausible fake needs: checkout and drop_buy (the cart, the drop
page). An action with no fake here falls through to the route, which then writes
normally — a trap chapter that wants more (W1 Ch8's ghost /account page) serves it
from an ext before_request or its own templates.

The login fake is the deception that matters most: the password is NOT checked and
the answer is the byte-identical wrong-password 401, so a credential-stuffing run
cannot tell a deceived attempt from a miss — every hit it reports is poisoned.
"""

import secrets

from flask import g, jsonify, redirect, request, url_for

from .. import gate
from ..models import utcnow


def _flash(msg, kind="ok"):
    g.ctx.session.set("flash", f"{kind}|{msg}")


def fake_response(action):
    """The fake answer for `action`, or None to let the route run (and write) as usual."""
    if action == "login":
        g.ctx.note(login="deceived")
        if gate.wants_json():
            return jsonify(error={"code": "invalid_credentials", "message": "Wrong email or password."}), 401
        from .pages import render
        _flash("Wrong email or password.", "warn")
        return render("login.html", next=request.form.get("next", "/account"),
                      email=request.form.get("email", "").strip().lower()), 401
    if action == "register":
        g.ctx.note(register="deceived")
        if gate.wants_json():
            body = request.get_json(silent=True) or request.form
            email = str(body.get("email", "")).strip().lower()
            return jsonify(ok=True, user={"email": email, "name": str(body.get("name", ""))[:80],
                                          "loyalty_points": 0, "saved_card": None,
                                          "created_at": utcnow().isoformat() + "Z", "addresses": []}), 201
        _flash("Welcome to Kestrel.")
        return redirect(url_for("pages.account"))
    if action == "review":
        g.ctx.note(review="deceived")
        sku = (request.view_args or {}).get("sku") or (request.get_json(silent=True) or {}).get("sku", "")
        if gate.wants_json():
            body = request.get_json(silent=True) or {}
            return jsonify(id=secrets.randbelow(90000) + 10000, sku=sku,
                           author=str(body.get("author", "Guest"))[:40],
                           rating=max(1, min(5, int(body.get("rating", 5) or 5))),
                           title=str(body.get("title", ""))[:120], body=str(body.get("body", ""))[:2000],
                           status="published", created_at=utcnow().isoformat() + "Z"), 201
        _flash("Thanks for your review.")
        return redirect(url_for("pages.product", sku=sku))
    if action == "newsletter":
        g.ctx.note(newsletter="deceived")
        if request.is_json:
            return {"ok": True}
        _flash("You're on the list.")
        return redirect(request.form.get("next") or url_for("pages.home"))
    return None
