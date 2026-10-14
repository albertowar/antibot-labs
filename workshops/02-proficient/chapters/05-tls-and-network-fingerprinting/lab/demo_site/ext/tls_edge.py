"""
The TLS edge bridge: how a measured fingerprint reaches the defenses.

    client --TLS--> fingerproxy :8443 --HTTP + X-JA4-Fingerprint, X-HTTP2-Fingerprint--> store

fingerproxy (tools/edge.py) terminates TLS, so it is the only thing that ever sees the
ClientHello and the HTTP/2 connection preface. It forwards what it measured as two request
headers. This middleware (outermost, ahead of the simulated lab edge) moves them out of the
header list and into the WSGI environ keys the gate reads (`lab.ja4_measured`, `lab.h2`), so
defenses see them as `ctx.edge.ja4` / `ctx.edge.h2` with `ctx.edge.ja4_source == "measured"`
and cannot tell the difference between "a header the client sent" and "a measurement":
neither is in `ctx.headers`.

Without a TLS edge the contract's other path still works: `X-Lab-JA4` is a *claimed* fingerprint
(`ctx.edge.ja4_source == "claimed"`, no HTTP/2 part). The 40 shoppers use it (they are Python and
cannot speak a browser's TLS); every attacker and the real-browser shoppers come through the edge.

Trust: these headers are only believable if the origin cannot be reached any other way. In
production that is a private network, mTLS between edge and origin, or a signed header; here the
store listens on loopback and only the lab clients are on it (Bonus 2 shows the hole).

Also here: /lab/tls/check, which shows what the edge measured for *your* connection (open it in
your own browser through https://localhost:8443), and an enricher that writes the fingerprint into
every decision-log row so tools/fingerprint_report.py can cluster the traffic afterwards.
"""

from flask import current_app, g, jsonify, render_template, request, Blueprint

from demo_site import gate, hooks


class TlsEdgeBridge:
    def __init__(self, app):
        self.app = app

    def __call__(self, environ, start_response):
        ja4 = environ.pop("HTTP_X_JA4_FINGERPRINT", "")
        h2 = environ.pop("HTTP_X_HTTP2_FINGERPRINT", "")
        environ.pop("HTTP_X_JA3_FINGERPRINT", None)      # JA3 is unstable for Chromium; the lab keys on JA4
        if ja4:
            environ["lab.ja4_measured"] = ja4
            environ["lab.h2"] = h2
        return self.app(environ, start_response)


def _note(ctx):
    """Every decision-log row carries the fingerprint, so Round 0 and the debrief can read it back."""
    from defenses import ja4 as ja4lib
    fp = ja4lib.fingerprint(ctx)
    ctx.note(ja4=fp.ja4, ja4_source=fp.source, h2=fp.h2, ja4_ab=fp.ja4_ab, h2_core=fp.h2_core, ua=ctx.ua.raw[:80])


bp = Blueprint("tls", __name__, url_prefix="/lab/tls")


@bp.route("/check")
def check():
    """What the TLS edge measured for this connection. Never blocked (it lives under /lab/)."""
    from defenses import ja4 as ja4lib
    g.ctx = ctx = gate.build_ctx(current_app)
    fp = ja4lib.fingerprint(ctx)
    claimed = ja4lib.claimed_engine(ctx.ua.raw)
    body = {"ja4": fp.ja4, "ja4_ab": fp.ja4_ab, "ja4_source": fp.source, "http2": fp.h2, "h2_core": fp.h2_core,
            "http_version": fp.http_version, "families": ja4lib.tls_families(fp), "tls_engine": ja4lib.tls_engine(fp, claimed),
            "user_agent": ctx.ua.raw, "claimed_engine": claimed, "level": ctx.level}
    if "text/html" in request.headers.get("Accept", "") and request.args.get("format") != "json":
        return render_template("tls/check.html", **body)
    return jsonify(body)


def init(app):
    app.wsgi_app = TlsEdgeBridge(app.wsgi_app)
    hooks.enricher(_note)
    app.register_blueprint(bp)
