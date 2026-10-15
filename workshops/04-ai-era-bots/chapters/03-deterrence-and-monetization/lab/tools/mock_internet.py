"""The operators' websites, on 127.0.0.1:5003.

Verifying a signed crawler means fetching the key directory its operator publishes at
`https://<origin>/.well-known/http-message-signatures-directory`. A lab cannot depend on a real
operator (and never sends lab traffic at a third party), so this one process plays both synthetic
operators, deterministically, with keys from tools/make_keys.py:

    GET  /dir/<host>/.well-known/http-message-signatures-directory
                         the operator's signed JWK Set (trainbot.example, labsearch.example)
    POST /reset          zero the counters
    GET  /stats          how many directory fetches the defender made (the verifier caches them)

Everything here is loopback only: the process binds 127.0.0.1 and
`labnet.require_local_env("MOCK_URL")` refuses a MOCK_URL that is not this machine. The store
starts it on a thread by default (demo_site/ext/identity.py); run it by hand with
`python tools/mock_internet.py` and MOCK_AUTOSTART=0 on the store to see the two-process shape.

Latency is simulated (FETCH_LATENCY_MS) so the verifier's directory cache shows up in the gate figure
the way it does in production. This is a trimmed copy of W4 Ch2's mock internet: no DNS, no range
files, no hosting panel, because this chapter's registry holds the ranges itself.
"""

from __future__ import annotations

import ipaddress
import json
import os
import sys
import threading
import time

from flask import Flask, Response, abort, jsonify, request

HERE = os.path.dirname(os.path.abspath(__file__))
LAB_DIR = os.path.dirname(HERE)
sys.path[:0] = [LAB_DIR, HERE]
import labnet  # noqa: E402  (the lab-root localhost guard)
from defenses import httpsig  # noqa: E402
import make_keys  # noqa: E402

FETCH_LATENCY_MS = float(os.environ.get("FETCH_LATENCY_MS", "30"))

app = Flask(__name__)
_lock = threading.Lock()
_keys = {owner: make_keys.load(owner) for owner in make_keys.OWNERS}      # generated on first use
state = {"dir": 0}


def _directory(host: str) -> dict:
    k = _keys[host]
    jwks = {"keys": [k["jwk"]]}
    headers = httpsig.sign_directory(jwks, {k["thumbprint"]: httpsig.load_private(k["seed_hex"])}, host)
    return {"jwks": jwks, "headers": headers}


@app.get("/dir/<host>/.well-known/http-message-signatures-directory")
def directory(host):
    time.sleep(FETCH_LATENCY_MS / 1000)
    host = host.lower()
    if host not in _keys:
        abort(404)
    with _lock:
        state["dir"] += 1
    entry = _directory(host)
    resp = Response(json.dumps(entry["jwks"]), mimetype=httpsig.DIRECTORY_MEDIA_TYPE)
    for k, v in entry["headers"].items():
        if k.lower() in ("signature", "signature-input"):
            resp.headers[k] = v
    resp.headers["Cache-Control"] = "max-age=86400"
    return resp


@app.post("/reset")
def reset():
    if not ipaddress.ip_address(request.remote_addr or "0.0.0.0").is_loopback:
        abort(403)
    with _lock:
        state["dir"] = 0
    return jsonify({"ok": True})


@app.get("/stats")
def stats():
    return jsonify({"mock": "w4ch3", **state})


@app.get("/")
def index():
    return Response("<h1>operator websites</h1><p>Signed key directories for the W4 Ch3 lab.</p>",
                    mimetype="text/html")


if __name__ == "__main__":
    labnet.require_local_env("MOCK_URL")          # a MOCK_URL that is not this machine is refused
    port = int(os.environ.get("MOCK_PORT", "5003"))
    print(f"operator websites on http://127.0.0.1:{port}  (fetch latency {FETCH_LATENCY_MS} ms)")
    app.run(host="127.0.0.1", port=port)
