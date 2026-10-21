"""Route blueprints and the helpers they share (cart, csrf, flash, action guards)."""

import secrets

from flask import current_app, g, jsonify, render_template, request

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
    """Run the ladder's action:<name> phase. Returns a response to short-circuit with, or None.

    A `deceive` verdict is answered here for the actions routes/deceive.py knows how to fake
    (login, register, review, newsletter); checkout and drop_buy keep their fake in the route,
    which holds the cart the fake confirmation needs (contract 1.7)."""
    g.ctx.note(**notes)
    d = gate.run_phase(f"action:{action}")
    r = gate.respond(d, g.ctx)
    if r is None and getattr(g, "deceive", False):
        from .deceive import fake_response
        return fake_response(action)
    return r


def after_action(action, response, **result):
    """Fire the post-write hooks for `action` and return the response.

    The write actions (review/checkout/drop_buy, and register since contract 1.7) call this on
    their success path, after the row is written, with the row(s) in `result` (e.g. order=order
    or user=u). Contract 1.8 adds the account changes (change=AccountChange, user=u, for
    change_email/change_password/address_add/card_add, plus change_cancel when the owner's link
    cancels one), gift_card_redeem (user=, gift_card=) and password_reset_confirm (user=). `login` calls it on EVERY attempt with result={"user": ..., "ok": bool,
    "reason": ...}, so a defense can meter failures or step up after a success. Each
    `hooks.on_action(action, fn)` handler is fn(ctx, result, response); it may mutate the
    persisted row (hold a review as `pending`, mark an order `pending`, attribute an agent
    order), take the session back (delete `uid`), and return a replacement response, or None
    to keep the current one. With nothing registered the response is returned unchanged, so
    the default store behaviour is identical."""
    from .. import hooks
    ctx = getattr(g, "ctx", None)
    for fn in hooks.ACTION_HOOKS.get(action, []):
        r = fn(ctx, result, response)
        if r is not None:
            response = r
    return response


def submit_change(kind, user, fields):
    """The write path every account change shares (HTML and JSON), contract 1.8.

    validate -> gate (`change_email` | `change_password` | `address_add` | `card_add`) -> row ->
    apply, hold or wait for the email link. Returns (change, early_response): early_response is
    whatever the gate answered, in which case nothing was written. Raises account.ChangeError for
    bad input (before the gate) and for a wrong current password (after it, so a defense still
    sees the attempt). A check that sets ctx.attrs["hold"] = {"hours", "reason"} parks the change."""
    from .. import account
    from ..models import AccountChange, db
    payload, extra, facts, proof = account.prepare_change(kind, fields, user, current_app.config["LAB"].hash_iters)
    if proof is not None:                                # same shape W2 Ch6's change_email check reads
        g.ctx.attrs["reauth"] = {"password_ok": proof}
    r = guard(account.ACTIONS[kind], **facts)
    if r:
        return None, r
    if kind == "password" and not proof:
        raise account.ChangeError("wrong_password", "That is not your current password.", 403)
    hold = g.ctx.attrs.get("hold")
    hold = hold if isinstance(hold, dict) and float(hold.get("hours") or 0) > 0 else None
    change = AccountChange(user_id=user.id, kind=kind, payload=payload, token=secrets.token_urlsafe(16),
                           status="confirm" if kind == "email" else "pending", extra=dict(extra, sid=g.ctx.session.sid))
    if hold:
        change.extra["hold"] = hold
    db.session.add(change)
    db.session.commit()
    if kind != "email":                                  # an email change waits for its link, hold or not
        account.hold_change(change, hold) if hold else account.apply_change(change)
    g.ctx.note(account_change=kind, change_status=change.status)
    return change, None


def settle_change(change, user, response, **result):
    """After the response is chosen: fire the action hooks, then mail the default notices (unless a
    check set ctx.attrs["notify"] = False). Returns the response a hook may have replaced."""
    from .. import account
    response = after_action(account.ACTIONS[change.kind], response, change=change, user=user, **result)
    if g.ctx.attrs.get("notify", True):
        account.notify(g.ctx.redis, change, user)
    return response


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
