"""
Chapter 6 — Mock CAPTCHA provider with a Turnstile-compatible API (port 5001)

A stand-in for a hosted CAPTCHA service, so the lab runs offline with no
account and no keys. It copies the contract that matters to YOUR server:

  GET  /turnstile/v0/api.js        widget script: renders a box, puts a
                                   token in the hidden input
                                   `cf-turnstile-response`
  POST /turnstile/v0/siteverify    secret + response (+ remoteip) →
                                   {"success", "challenge_ts", "hostname",
                                    "action", "cdata", "error-codes"}

Like the real service, tokens are single use, expire after 300 s, and carry
the hostname and action they were minted for. Unlike the real service,
the "challenge" always passes, just like Cloudflare's always-pass test
sitekey. This lab is about what your server does with the token, and the
README's rules of engagement model what tokens cost an attacker.

Its domain allowlist is off, the way test keys and many misconfigured
sitekeys behave, so a page on another hostname can mint tokens for your
sitekey. Checking `hostname` is your job.

Lab-only endpoints:
  POST /lab/mint    what the widget calls after a pass
  POST /lab/chaos   {"mode": "ok" | "error", "seconds": 5}: simulate an
                    outage (siteverify returns HTTP 500 for a few seconds)
  POST /lab/reset   forget every token
"""

import os
import secrets
import sys
import threading
import time
from datetime import datetime, timezone

from flask import Flask, Response, jsonify, request

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from labkit import SECRET, SITEKEY  # noqa: E402

TOKEN_TTL_S = 300
app = Flask(__name__)
_tokens = {}
_lock = threading.Lock()
_chaos_until = 0.0

WIDGET_JS = """
(function () {
  document.querySelectorAll('.cf-turnstile').forEach(async function (el) {
    el.style.cssText = 'display:inline-block;padding:10px 14px;border:1px solid #888;' +
                       'border-radius:6px;font:14px sans-serif';
    el.textContent = 'Verifying…';
    const r = await fetch('%(origin)s/lab/mint', {
      method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({sitekey: el.dataset.sitekey, action: el.dataset.action || '',
                            cdata: el.dataset.cdata || '', hostname: location.hostname})});
    const input = document.createElement('input');
    input.type = 'hidden'; input.name = 'cf-turnstile-response';
    input.value = (await r.json()).token;
    el.textContent = '✔ Success! (mock provider)';
    el.closest('form').appendChild(input);
  });
})();
"""


def _now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


@app.after_request
def cors(resp):
    # The widget calls /lab/mint from the demo store's origin.
    resp.headers["Access-Control-Allow-Origin"] = "*"
    resp.headers["Access-Control-Allow-Headers"] = "Content-Type"
    return resp


@app.get("/turnstile/v0/api.js")
def widget():
    return Response(WIDGET_JS % {"origin": request.host_url.rstrip("/")},
                    mimetype="application/javascript")


@app.route("/lab/mint", methods=["POST", "OPTIONS"])
def mint():
    if request.method == "OPTIONS":
        return "", 204
    data = request.get_json(force=True)
    if data.get("sitekey") != SITEKEY:
        return jsonify({"error": "unknown sitekey"}), 400
    token = "0." + secrets.token_urlsafe(96)
    with _lock:
        _tokens[token] = {
            "hostname": data.get("hostname", ""), "action": data.get("action", ""),
            "cdata": data.get("cdata", ""), "challenge_ts": _now_iso(),
            "minted_at": time.time(), "spent": False,
            "minted_by": request.headers.get("X-Lab-Client-IP", request.remote_addr),
        }
    return jsonify({"token": token})


@app.post("/turnstile/v0/siteverify")
def siteverify():
    if time.time() < _chaos_until:
        return Response("<html><h1>502 Bad Gateway</h1></html>", status=500,
                        mimetype="text/html")
    data = request.form if request.form else (request.get_json(silent=True) or {})
    secret, token = data.get("secret"), data.get("response")

    def fail(*codes):
        return jsonify({"success": False, "error-codes": list(codes)})

    if not secret:
        return fail("missing-input-secret")
    if secret != SECRET:
        return fail("invalid-input-secret")
    if not token:
        return fail("missing-input-response")
    with _lock:
        record = _tokens.get(token)
        if record is None or len(token) > 2048:
            return fail("invalid-input-response")
        if record["spent"] or time.time() - record["minted_at"] > TOKEN_TTL_S:
            return fail("timeout-or-duplicate")
        record["spent"] = True
    return jsonify({"success": True, "challenge_ts": record["challenge_ts"],
                    "hostname": record["hostname"], "action": record["action"],
                    "cdata": record["cdata"], "error-codes": []})


@app.post("/lab/chaos")
def chaos():
    global _chaos_until
    data = request.get_json(force=True)
    seconds = min(float(data.get("seconds", 5)), 30)
    _chaos_until = time.time() + seconds if data.get("mode") == "error" else 0.0
    return jsonify({"mode": data.get("mode"), "seconds": seconds})


@app.post("/lab/reset")
def reset():
    global _chaos_until
    with _lock:
        _tokens.clear()
    _chaos_until = 0.0
    return jsonify({"ok": True})


@app.get("/lab/health")
def health():
    return jsonify({"ok": True, "tokens": len(_tokens)})


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.environ.get("PROVIDER_PORT", "5001")),
            threaded=True)
