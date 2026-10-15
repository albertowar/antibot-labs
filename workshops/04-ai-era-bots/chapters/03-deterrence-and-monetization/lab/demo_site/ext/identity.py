"""W4 Ch3 extension: what the identity checks need from the store that the gate does not give them.

  * The operators' websites. Verifying a signed crawler means fetching its operator's key
    directory. tools/mock_internet.py plays both synthetic operators on 127.0.0.1:5003 and this
    module starts it on a thread unless one of ours already answers at MOCK_URL (MOCK_AUTOSTART=0 to
    run it in its own terminal; a busy port falls back to a free one and sets MOCK_URL). It is a
    side service, not the store: every client reaches it through the `labnet` guard. It starts
    before anything else, because a directory fetch that fails is negative-cached for five minutes.
  * The raw query string and the scheme. A Web Bot Auth signature can cover `@query` or
    `@target-uri`, which are built from the query string exactly as sent. The gate's `ctx.args` is
    parsed (order, repeats and percent-escapes lost), so an enricher exposes
    `request.query_string` as ctx.attrs["raw_query"] (and the scheme as ctx.attrs["scheme"]), the
    way W4 Ch2's ext does, so the shared verifier can rebuild the signature base.
  * POST /lab/reset also resets the mock's counters.
"""

import os
import socket
import sys
import threading

import httpx
from flask import request

import labnet

from .. import hooks

LAB = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))


def _is_ours(url):
    try:
        r = httpx.get(f"{url}/stats", timeout=1)
        return r.status_code == 200 and r.json().get("mock") == "w4ch3"
    except (httpx.HTTPError, ValueError):
        return False


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def start_mock():
    """Make sure the operators' websites are answering; sets and returns MOCK_URL."""
    url = os.environ.get("MOCK_URL", f"http://127.0.0.1:{os.environ.get('MOCK_PORT', '5003')}").rstrip("/")
    labnet.require_local(url, what="MOCK_URL")
    if os.environ.get("MOCK_AUTOSTART", "1") == "0" or _is_ours(url):
        os.environ["MOCK_URL"] = url
        return url
    sys.path[:0] = [os.path.join(LAB, "tools")]
    import mock_internet
    from werkzeug.serving import make_server
    port = int(url.rsplit(":", 1)[1])
    try:
        srv = make_server("127.0.0.1", port, mock_internet.app, threaded=True)
    except OSError:
        port = _free_port()
        srv = make_server("127.0.0.1", port, mock_internet.app, threaded=True)
    threading.Thread(target=srv.serve_forever, daemon=True, name="mock-internet").start()
    os.environ["MOCK_URL"] = f"http://127.0.0.1:{port}"
    return os.environ["MOCK_URL"]


def _reset_mock(app):
    try:
        httpx.post(f"{os.environ['MOCK_URL']}/reset", timeout=2)
    except httpx.HTTPError:
        pass


def _raw_query(ctx):
    """Enricher: the query string as the client sent it, and the scheme, for signature bases."""
    ctx.attrs["raw_query"] = request.query_string.decode("latin-1")
    ctx.attrs["scheme"] = request.scheme


def init(app):
    start_mock()
    hooks.enricher(_raw_query)
    hooks.on_reset(_reset_mock)
