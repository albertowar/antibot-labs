"""
The engine-proof collector (Round 4's evidence): a script on every store page and the `engine`
telemetry kind it reports to. The finished logic is defenses/engine_signals.py; the layer that
demands the proof is defenses/browser_proof.py (Round 4's TODO).

The script runs at every level, so Rounds 0-3 already collect proofs; they just are not asked for.
"""

from flask import g

from demo_site import hooks


def _nonce():
    """Jinja global for the slot template: the session's nonce, or '' on a page with no Ctx."""
    from defenses import engine_signals
    ctx = getattr(g, "ctx", None)
    return engine_signals.issue_nonce(ctx) if ctx is not None else ""


def _report(ctx, payload):
    """POST /api/telemetry {"kind": "engine", nonce, error_message, eval_length}."""
    from defenses import engine_signals, ja4
    fp = ja4.fingerprint(ctx)
    if not fp.present:
        return {"ok": False, "error": "no TLS fingerprint on this connection"}
    if not engine_signals.nonce_valid(ctx, payload.get("nonce")):
        return {"ok": False, "error": "bad nonce"}
    engine = engine_signals.classify_engine(payload.get("error_message", ""), payload.get("eval_length", 0))
    if engine is None:
        return {"ok": False, "error": "unrecognised JS engine"}
    engine_signals.record_proof(ctx, engine, fp.ja4_b)
    return {"ok": True, "engine": engine}


def init(app):
    app.jinja_env.globals["tls_nonce"] = _nonce
    hooks.slot("body_end", "tls/engine.html")
    hooks.telemetry.register("engine", lambda ctx, payload: _report(ctx, payload))
