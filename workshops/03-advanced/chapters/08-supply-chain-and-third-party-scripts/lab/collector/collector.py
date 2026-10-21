"""
collector.py: the attacker's exfil sink (LAB-LOCAL ONLY).

Stands in for "attacker.example.com" in the real world. It binds to 127.0.0.1 so nothing leaves the
laptop, its address comes from COLLECTOR_URL through the labnet guard (a non-local value ends the
process), and it simply counts and stores whatever a skimmer manages to send. The attacks and the
scoreboard read /captured to answer the only question that matters: did any card data get out?

Accepts both exfil shapes a skimmer uses:
  POST /collect        body = JSON  (sendBeacon / fetch)
  GET  /collect?d=...  query        (an <img> pixel)

Run:
  python collector/collector.py            # http://127.0.0.1:5001   (COLLECTOR_URL to change the port)
"""

import json
import os
import sys
from collections import deque
from datetime import datetime, timezone
from urllib.parse import urlparse

from flask import Flask, jsonify, request

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))  # lab root: labnet.py
from labnet import require_local_env, target  # noqa: E402

app = Flask(__name__)
_captured: deque = deque(maxlen=500)
SENSITIVE = ("card", "cvc", "password")      # the starter's field names: a capture counts only with one of these


def _record(via: str, payload):
    fields = {}
    src = via
    if isinstance(payload, dict):
        fields = payload.get("fields", payload)
        src = payload.get("src", via)
    _captured.appendleft({"ts": datetime.now(timezone.utc).isoformat(), "via": via, "src": src,
                          "sensitive": any(k in (fields or {}) for k in SENSITIVE), "fields": sorted(fields or {})})


@app.route("/collect", methods=["POST"])
def collect_post():
    payload = request.get_json(force=True, silent=True)
    if payload is None:
        try:
            payload = json.loads(request.get_data(as_text=True) or "{}")
        except ValueError:
            payload = {"raw": request.get_data(as_text=True)}
    _record("beacon", payload)
    return "", 204


@app.route("/collect", methods=["GET"])
def collect_get():
    raw = request.args.get("d", "")
    try:
        payload = json.loads(raw)
    except ValueError:
        payload = {"raw": raw}
    _record("pixel", payload)
    gif = (b"GIF89a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\x00\x00\x00!\xf9\x04\x01\x00\x00\x00\x00,\x00\x00\x00"
           b"\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;")      # 1x1 transparent gif so the <img> load succeeds
    return gif, 200, {"Content-Type": "image/gif"}


@app.route("/captured")
def captured():
    items = list(_captured)
    return jsonify({"total": len(items), "sensitive": sum(1 for c in items if c["sensitive"]), "items": items[:20]})


@app.route("/reset", methods=["POST", "GET"])
def reset():
    _captured.clear()
    return jsonify({"ok": True, "total": 0})


@app.after_request
def _cors(resp):
    """A real sink answers cross-origin writes; the skimmer never reads the reply, so this only quiets the console."""
    resp.headers["Access-Control-Allow-Origin"] = "*"
    return resp


if __name__ == "__main__":
    require_local_env("COLLECTOR_URL")
    url = target("COLLECTOR_URL", "http://127.0.0.1:5001")
    port = urlparse(url).port or 5001
    print(f"Attacker collector (LAB-LOCAL) on http://127.0.0.1:{port}  (GET /captured for the tally)")
    app.run(host="127.0.0.1", port=port, debug=False)
