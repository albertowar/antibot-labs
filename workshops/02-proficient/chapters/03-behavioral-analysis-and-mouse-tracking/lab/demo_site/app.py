"""
Chapter 3 Lab: limited-drop store with behavioral scoring.

A sneaker drop: 50 pairs, one reservation form. Scalper bots want all 50.
The page loads static/collector.js, which records pointer paths, clicks and
keystroke timing; the telemetry rides along with the reservation, and the
server scores it with the layers enabled by DEFENSE_LEVEL (0-4):

    DEFENSE_LEVEL=0 python app.py   # Round 0: score and log, never stop anyone
    DEFENSE_LEVEL=1 python app.py   # + L1 presence & sanity
    DEFENSE_LEVEL=2 python app.py   # + L2 kinematics & keystroke dynamics
    DEFENSE_LEVEL=3 python app.py   # + L3 motor-control realism
    DEFENSE_LEVEL=4 python app.py   # + L4 layout jitter & replay signatures

Verdicts (defenses/scoring.py):
    score >= 60  block      403
    score >= 30  challenge  202  (in production: a CAPTCHA or PoW step-up, W1 Ch5/Ch6)
    score <  30  allow      200  reserved

Debug endpoints (never scored):
    /behavior/sessions        last decisions, with labels and reasons
    /behavior/trace/<sid>     raw telemetry + features for one session ("latest" works)
    /behavior/view/<sid>      draws the path, clicks and speed profile

Storage: Redis from ../docker-compose.yml (STORE=memory to run without Docker).
Every /api/reserve response carries `Server-Timing: behaviorscore;dur=<ms>`
so the checkpoint can report what scoring costs, not just what it catches.
"""

import json
import os
import random
import secrets
import sys
import time

from flask import Flask, abort, jsonify, redirect, render_template_string, request

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [HERE, os.path.join(HERE, "..", "defenses")]

from features import extract   # noqa: E402
from scoring import evaluate    # noqa: E402
from store import open_store    # noqa: E402

DEFENSE_LEVEL = int(os.environ.get("DEFENSE_LEVEL", "0"))
PORT = int(os.environ.get("PORT", "5000"))

app = Flask(__name__, static_folder=os.path.join(HERE, "static"))
store = open_store()

# Base layout in page pixels. Every element is absolutely positioned with a
# fixed size, so the server knows exactly where each box is drawn.
FIELDS = {"name": (0, 120, 320, 36), "email": (0, 190, 320, 36), "size": (0, 260, 120, 36)}
BUTTON = (0, 330, 160, 44)
BASE_ORIGIN = (360, 200)


def new_layout():
    """
    Where the form is drawn for this session.

    Levels 0-3 always use the same layout. At level 4 the form and the button
    move a little every session (L4 "layout jitter"): a recorded trace that
    clicked (520, 552) last time now clicks empty page. Real users don't notice
    a form that is 100 px to the left; replay bots have to adapt.
    """
    ox, oy = BASE_ORIGIN
    bx = 0
    if DEFENSE_LEVEL >= 4:
        ox += random.randint(-140, 140)
        oy += random.randint(-80, 80)
        bx = random.randint(0, 160)
    boxes = {name: [ox + x, oy + y, w, h] for name, (x, y, w, h) in FIELDS.items()}
    x, y, w, h = BUTTON
    boxes["reserve"] = [ox + bx + x, oy + y, w, h]
    return {"origin": [ox, oy], "boxes": boxes}


def new_session():
    sid = secrets.token_urlsafe(12)
    session = {"sid": sid, "created": time.time(), "layout": new_layout()}
    store.put_session(sid, session)
    return session


def client_label():
    """Lab scripts label their traffic so /behavior/sessions is readable.
    Browsers send nothing and show up as "browser". (Never trust this in production.)"""
    return request.headers.get("X-Lab-Client", "browser")[:40]


DROP_HTML = """<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Aurora Runner: limited drop</title>
<style>
  html, body { margin: 0; padding: 0; }
  body { font-family: system-ui, sans-serif; min-height: 1100px; background: #fafafa; }
  .abs { position: absolute; box-sizing: border-box; }
  #hdr { left: {{ o[0] }}px; top: {{ o[1] }}px; width: 460px; }
  #hdr h1 { margin: 0 0 .3rem; font-size: 1.6rem; }
  #hdr p { margin: 0; color: #555; }
  input.abs { font-size: 15px; padding: 0 10px; border: 1px solid #aaa; border-radius: 6px; }
  #reserve { font-size: 16px; font-weight: 600; border: 0; border-radius: 8px;
             background: #111; color: #fff; cursor: pointer; }
  #result { left: {{ o[0] }}px; top: {{ o[1] + 400 }}px; width: 520px; font-size: 14px; }
  .lvl { position: fixed; right: 12px; top: 8px; font: 12px monospace; color: #888; }
  .story { position: absolute; left: 40px; top: 760px; width: 700px; color: #444; }
</style></head>
<body>
  <div class="lvl">DEFENSE_LEVEL={{ level }} &middot; <a href="/behavior/sessions">sessions</a></div>
  <form id="drop" autocomplete="on">
    <div id="hdr" class="abs">
      <h1>Aurora Runner &mdash; limited drop</h1>
      <p>50 pairs. One per customer. Fill in the form and reserve.</p>
    </div>
    {% for name, ph, ac in [("name", "Full name", "name"), ("email", "Email", "email"), ("size", "EU size", "off")] %}
    {% set b = boxes[name] %}
    <input id="{{ name }}" name="{{ name }}" class="abs" placeholder="{{ ph }}" autocomplete="{{ ac }}"
           style="left:{{ b[0] }}px;top:{{ b[1] }}px;width:{{ b[2] }}px;height:{{ b[3] }}px">
    {% endfor %}
    {% set b = boxes["reserve"] %}
    <button id="reserve" type="submit" class="abs"
            style="left:{{ b[0] }}px;top:{{ b[1] }}px;width:{{ b[2] }}px;height:{{ b[3] }}px">Reserve</button>
  </form>
  <div id="result" class="abs"></div>
  <div class="story">
    <h3>About the drop</h3>
    <p>The Aurora Runner is a fictional shoe for a fictional store. This page exists so you can
       watch the difference between how people and scripts fill in a form.</p>
  </div>
  <script src="/static/collector.js"></script>
  <script>
    const SID = {{ sid|tojson }};
    document.getElementById("drop").addEventListener("submit", async (ev) => {
      ev.preventDefault();
      const form = Object.fromEntries(new FormData(ev.target).entries());
      const telemetry = window.behaviorCollector.snapshot();
      const r = await fetch("/api/reserve", {
        method: "POST", headers: {"Content-Type": "application/json"},
        body: JSON.stringify({sid: SID, form, telemetry}),
      });
      const body = await r.json();
      window.lastReserve = body;          // lab scripts read the verdict from here
      const out = document.getElementById("result");
      out.dataset.status = body.status;
      out.innerHTML = `<b>${body.status.toUpperCase()}</b> (score ${body.score}) ` +
        `<a href="/behavior/view/${SID}">view my trace</a><br>` +
        (body.reasons || []).map(x => `&bull; ${x}`).join("<br>");
    });
  </script>
</body>
</html>"""


@app.route("/")
def index():
    return redirect("/drop")


@app.route("/drop")
def drop():
    session = new_session()
    return render_template_string(DROP_HTML, sid=session["sid"], level=DEFENSE_LEVEL,
                                  o=session["layout"]["origin"], boxes=session["layout"]["boxes"])


@app.route("/api/session", methods=["POST"])
def api_session():
    """The same session the page gets, as JSON. tools/humans.py uses it to
    build synthetic users for the layout the server drew."""
    session = new_session()
    return jsonify({"sid": session["sid"], "layout": session["layout"], "level": DEFENSE_LEVEL})


@app.route("/api/reserve", methods=["POST"])
def api_reserve():
    body = request.get_json(silent=True) or {}
    telemetry = body.get("telemetry") or {}
    session = store.pop_session(str(body.get("sid", "")))
    if session is None:
        return jsonify({"status": "blocked", "score": 100,
                        "reasons": ["Unknown, expired or reused session"]}), 403

    started = time.perf_counter()
    feats = extract(telemetry, session["layout"])
    score, reasons, verdict, signature = evaluate(
        telemetry, feats, session["layout"], DEFENSE_LEVEL, store, session["sid"])
    score_ms = (time.perf_counter() - started) * 1000
    store.add_signature(session["sid"], signature)    # remembered at every level

    payload_bytes = len(request.get_data())
    label = client_label()
    store.add_decision({
        "sid": session["sid"], "t": round(time.time(), 1), "label": label, "level": DEFENSE_LEVEL,
        "verdict": verdict, "score": score, "reasons": reasons, "score_ms": round(score_ms, 3),
        "bytes": payload_bytes, "points": len(telemetry.get("pointer", [])),
    })
    store.put_trace(session["sid"], {
        "sid": session["sid"], "label": label, "level": DEFENSE_LEVEL, "layout": session["layout"],
        "telemetry": telemetry, "verdict": verdict, "score": score, "reasons": reasons,
        # keep only field lengths: traces are shared with classmates in Round 4
        "form_lengths": {k: len(str(v)) for k, v in (body.get("form") or {}).items()},
    })

    status = {"allow": "reserved", "challenge": "challenge", "block": "blocked"}[verdict]
    code = {"allow": 200, "challenge": 202, "block": 403}[verdict]
    # Teaching only: in production never tell the client which rule fired.
    response = jsonify({"status": status, "score": score, "reasons": reasons, "sid": session["sid"]})
    response.status_code = code
    response.headers["Server-Timing"] = f"behaviorscore;dur={score_ms:.3f}"
    return response


@app.route("/behavior/sessions")
def behavior_sessions():
    return jsonify({"level": DEFENSE_LEVEL, "decisions": store.decisions(int(request.args.get("n", 30)))})


def find_trace(sid):
    if sid == "latest":
        label = request.args.get("label", "browser")
        for d in store.decisions(200):
            if d["label"] == label:
                sid = d["sid"]
                break
    return store.get_trace(sid)


@app.route("/behavior/trace/<sid>")
def behavior_trace(sid):
    trace = find_trace(sid)
    if trace is None:
        abort(404)
    trace = dict(trace)
    trace["features"] = extract(trace["telemetry"], trace["layout"])
    return jsonify(trace)


VIEW_HTML = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Trace {{ sid }}</title>
<style>body{font-family:system-ui;margin:1rem}canvas{border:1px solid #ccc;background:#fff}
pre{font-size:12px;background:#f4f4f4;padding:.5rem;max-width:1280px;overflow:auto}</style></head>
<body>
  <h2>Trace <code>{{ sid }}</code> <small id="meta"></small></h2>
  <canvas id="path" width="1280" height="720"></canvas>
  <h3>Closing speed of each approach to a click (px/ms over time)</h3>
  <canvas id="speed" width="1280" height="260"></canvas>
  <h3>Keystrokes (bar = key held down)</h3>
  <canvas id="keys" width="1280" height="120"></canvas>
  <h3>Features</h3><pre id="feats"></pre>
  <script src="/static/viewer.js"></script>
  <script>drawTrace({{ sid|tojson }});</script>
</body></html>"""


@app.route("/behavior/view/<sid>")
def behavior_view(sid):
    return render_template_string(VIEW_HTML, sid=sid)


if __name__ == "__main__":
    print(f" * DEFENSE_LEVEL={DEFENSE_LEVEL}  store={type(store).__name__}  http://localhost:{PORT}/drop")
    app.run(host="127.0.0.1", port=PORT, debug=False, threaded=True)
