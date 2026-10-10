"""
collector.py — the attacker's exfil sink (LAB-LOCAL ONLY).

Stands in for "attacker.example.com" in the real world. It binds to 127.0.0.1
so nothing leaves the laptop, and it simply counts and stores whatever a
skimmer manages to send. The scoreboard reads /captured to answer the only
question that matters: did any card data get out this round?

Accepts both exfil shapes a skimmer uses:
  POST /collect        body = JSON  (sendBeacon / fetch)
  GET  /collect?d=...  query        (an <img> pixel)

Run:
  python collector.py            # 127.0.0.1:5001
"""

import json
import os
from collections import deque
from datetime import datetime, timezone

from flask import Flask, jsonify, request

app = Flask(__name__)

_captured: deque = deque(maxlen=500)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _record(via: str, payload):
    fields = {}
    src = via
    if isinstance(payload, dict):
        fields = payload.get("fields", payload)
        src = payload.get("src", via)
    # A capture "counts" only if it carried a card number or a password.
    sensitive = any(k in (fields or {}) for k in ("card_number", "cvv", "password"))
    _captured.appendleft({
        "ts": _now(), "via": via, "src": src,
        "sensitive": sensitive, "fields": fields,
    })


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
    # 1x1 transparent gif so the <img> load succeeds
    gif = (b"GIF89a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\x00\x00\x00!"
           b"\xf9\x04\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;")
    return gif, 200, {"Content-Type": "image/gif"}


@app.route("/captured")
def captured():
    items = list(_captured)
    return jsonify({
        "total": len(items),
        "sensitive": sum(1 for c in items if c["sensitive"]),
        "items": items[:20],
    })


@app.route("/reset", methods=["POST", "GET"])
def reset():
    _captured.clear()
    return jsonify({"ok": True, "total": 0})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5001"))
    print(f"Attacker collector (LAB-LOCAL) on http://127.0.0.1:{port}  — GET /captured for the tally")
    app.run(host="127.0.0.1", port=port, debug=False)
