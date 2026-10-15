"""
Chapter 1: the glue between the sensor (demo_site/static/js/sensor.js) and the layer checks.

The store page carries a one-time nonce (demo_site/ext/sensor.py). The sensor collects raw facts
about the JavaScript environment and posts them, with that nonce, to the store's telemetry sink:
POST /api/telemetry {"kind": "sensor", "nonce": ..., "signals": {...}}. The ext module checks the
nonce (this session's, unused, younger than policy.NONCE_TTL) and keeps the signals as this
session's sensor report for policy.SENSOR_TTL. Every check below reads that report:

    report(ctx)          the session's latest valid sensor report, or None
    headers(ctx)         the request's headers as a case-insensitive mapping (for the JS-vs-HTTP checks)
    signals(...)         a layer's (points, reasons) as one pipeline Signal, reasons in the log

Only the gated paths (policy.SENSOR_GATED: the product API and the cart) are scored. The store's
HTML pages stay open: they are where the sensor runs. The sensor never learns its verdict: the
scores live server-side, so the rules can change without shipping new JavaScript.
"""

import json
import time

from . import policy
from .pipeline import Signal

REPORT = "report"


def key(ctx):
    return ctx.session.ns("sensor") + REPORT


def store_report(ctx, signals):
    ctx.redis.set(key(ctx), json.dumps({"at": time.time(), "signals": signals}), ex=policy.SENSOR_TTL)


def report(ctx):
    """This session's sensor signals, or None (no valid report, or it expired)."""
    if "sensor" not in ctx.attrs:
        raw = ctx.redis.get(key(ctx))
        ctx.attrs["sensor"] = json.loads(raw)["signals"] if raw else None
    return ctx.attrs["sensor"]


def gated(ctx):
    return ctx.path in policy.SENSOR_GATED


class _Headers:
    """`headers.get(name, default)` over the Ctx's ordered header list, case-insensitive."""

    def __init__(self, ctx):
        self.ctx = ctx

    def get(self, name, default=None):
        return self.ctx.header(name, default)


def headers(ctx):
    return _Headers(ctx)


def signals(layer, points, reasons, ctx):
    """One Signal for a layer's score; its reasons go to the decision log (`extra.sensor_reasons`)."""
    if not points and not reasons:
        return []
    ctx.notes.setdefault("sensor_reasons", []).extend(f"[{layer}] {r}" for r in reasons)
    return [Signal(layer, "flagged" if points else "noted", points, "; ".join(reasons)[:300])]


def layer_check(layer, score_fn, with_headers=False):
    """A request-phase check fn that scores the sensor report with `score_fn` on the gated paths."""
    def fn(ctx):
        if not gated(ctx):
            return None
        sig = report(ctx)
        if sig is None:
            return None                       # the sensor gate (defenses/sensor_gate.py) handles "no report"
        points, reasons = score_fn(sig, headers(ctx)) if with_headers else score_fn(sig)
        return signals(layer, points, reasons, ctx)
    return fn
