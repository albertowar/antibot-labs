"""
Capstone feature module: the drop, as the capstone's checks need to see it.

    enricher          stamps the session with what Chapter 5's session_guard reads: `js_nonce` (the page script
                      turns it into the js_ok cookie), `ua_hash` (the browser identity at session start) and
                      `landing` (the session loaded "/"). The same plumbing Chapter 5's promo module adds.
    hooks.slot        body_end: the one-line script that sets the js_ok cookie
                      form:drop: Chapter 8's trap fields (the honeypot and the timing token) inside the drop form
    after_request     counts a purchase on the session (the one-per-customer cap reads it)

No route here: the drop itself is the starter's /drop/<sku> and /api/buy. Ext modules are not
hot-reloaded: restart the store after editing this file.
"""

import hashlib
import secrets

from flask import g, request

from demo_site import hooks


def _ua_hash(ctx):
    """A browser's identity for this session: User-Agent plus the Client Hints brand list (Chapter 5's recipe)."""
    ua = ctx.header("User-Agent", "") or ""
    ch = ctx.header("Sec-CH-UA", "") or ""
    return hashlib.sha256(f"{ua}|{ch}".encode()).hexdigest()[:16]


def _enrich(ctx):
    s = ctx.session
    if s.new or not s.get("js_nonce"):
        s.set("js_nonce", secrets.token_hex(8))
        s.set("ua_hash", _ua_hash(ctx))
    if ctx.path == "/" and not s.get("landing"):
        s.set("landing", "1")


def _count_purchase(response):
    ctx = getattr(g, "ctx", None)
    if ctx is not None and getattr(g, "purchased", False) and request.path.startswith(("/drop/", "/api/buy")):
        ctx.session.incr("drop_purchases")
    return response


def init(app):
    hooks.enricher(_enrich)
    hooks.slot("body_end", "drop/js_cookie.html")
    hooks.slot("form:drop", "traps/fields.html")
    app.after_request(_count_purchase)
