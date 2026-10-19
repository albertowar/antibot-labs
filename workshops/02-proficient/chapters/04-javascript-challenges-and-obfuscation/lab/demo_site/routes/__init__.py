"""Route blueprints and the helpers they share (cart, csrf, flash, action guards)."""

import secrets

from flask import g, jsonify, render_template, request

from .. import gate


def current_user():
    return g.ctx.user if getattr(g, "ctx", None) else None


def csrf_token():
    tok = g.ctx.session.get("csrf")
    if not tok:
        tok = secrets.token_urlsafe(16)
        g.ctx.session.set("csrf", tok)
    return tok


def csrf_ok():
    """HTML forms carry a hidden csrf field; JSON routes rely on SameSite cookies instead."""
    if request.is_json:
        return True
    return request.form.get("csrf", "") == g.ctx.session.get("csrf", "-")


def guard(action, **notes):
    """Run the ladder's action:<name> phase. Returns a response to short-circuit with, or None."""
    g.ctx.note(**notes)
    d = gate.run_phase(f"action:{action}")
    return gate.respond(d, g.ctx)


def api_error(code, message, status=400, **extra):
    body = {"error": {"code": code, "message": message}}
    body.update(extra)
    return jsonify(body), status


class Cart:
    """The session's cart: a Redis hash of "sku|size" -> qty."""

    def __init__(self, ctx):
        self.redis, self.key = ctx.redis, ctx.session.ns("cart") + "items"

    def add(self, sku, size, qty=1):
        self.redis.hincrby(self.key, f"{sku}|{size}", qty)
        self.redis.expire(self.key, 7 * 24 * 3600)

    def remove(self, sku, size):
        self.redis.hdel(self.key, f"{sku}|{size}")

    def clear(self):
        self.redis.delete(self.key)

    def lines(self):
        from ..models import Product
        out = []
        for k, qty in self.redis.hgetall(self.key).items():
            sku, _, size = k.partition("|")
            p = Product.query.filter_by(sku=sku).first()
            if p:
                out.append({"product": p, "sku": sku, "size": size, "qty": int(qty), "line_cents": p.price_cents * int(qty)})
        return out

    def count(self):
        return sum(int(v) for v in self.redis.hvals(self.key))

    def total_cents(self):
        return sum(line["line_cents"] for line in self.lines())


def render(template, **ctx):
    return render_template(template, csrf=csrf_token(), **ctx)
