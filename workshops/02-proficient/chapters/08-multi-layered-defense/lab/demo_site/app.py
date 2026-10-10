"""
Chapter 8 Lab: the demo store's login, defended by a multi-layer pipeline.

Restart with the round's level (Flask's reloader also restarts it when you
edit anything under ../defenses):

    DEFENSE_LEVEL=0 python app.py   # Round 0: shadow mode, log only
    DEFENSE_LEVEL=1 python app.py   # Round 1: veto chain
    DEFENSE_LEVEL=2 python app.py   # Round 2: risk score + response ladder
    DEFENSE_LEVEL=3 python app.py   # Round 3: + correlation, opaque/deceptive responses
    DEFENSE_LEVEL=4 python app.py   # Round 4: + campaign layer, step-up

Flow of one login, the same for browsers, simulated humans and bots:

    GET  /login        form + collector script; sets the `sid` session cookie
    POST /telemetry    collector posts fingerprint + behaviour trace
    POST /login        pipeline scores it -> allow | pow | step_up | block
    POST /login        again with X-PoW: <nonce>      (after a pow challenge)
    POST /login/verify {"code": ...}                   (after a step-up)

Lab-only endpoints (localhost, never in production):
    GET  /lab/status            current level and store
    POST /lab/reset             wipe counters and the decision log
    GET  /lab/mailbox/<user>    the user's inbox; only the simulated *real*
                                users may read it (tools/population.py)

Every decision is appended to ../decision_log.jsonl. tools/checkpoint.py,
tools/layer_report.py and tools/sweep.py read it.
"""

import json
import os
import secrets
import sys
import threading
import time

from flask import Flask, g, jsonify, make_response, render_template_string, request

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "defenses"))

import campaign  # noqa: E402
import edge  # noqa: E402
import ladder  # noqa: E402
import store  # noqa: E402
import telemetry  # noqa: E402
import users  # noqa: E402
from pipeline import Context, evaluate  # noqa: E402
from sensors.headers import parse_ua  # noqa: E402

DEFENSE_LEVEL = int(os.environ.get("DEFENSE_LEVEL", "0"))
LOG_PATH = os.environ.get("DECISION_LOG", os.path.join(HERE, "..", "decision_log.jsonl"))
STORE_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")

app = Flask(__name__)
counters = store.Counters(store.connect(STORE_URL))
USERS = users.build()
_log_lock = threading.Lock()


def log(entry):
    entry.update(ts=round(time.time(), 3), level=DEFENSE_LEVEL)
    with _log_lock, open(LOG_PATH, "a") as f:
        f.write(json.dumps(entry) + "\n")


def session_id():
    return request.cookies.get("sid") or secrets.token_hex(12)


def password_verdict(cred):
    """The honest answer. A deceptive block (level 3+) must be byte-identical to the 401."""
    if cred == "valid":
        return jsonify({"ok": True}), 200
    return jsonify({"error": "Invalid credentials"}), 401


def respond(decision, cred, sid, username):
    """Turn a Decision into a response, and choose how much the client learns."""
    leaky = DEFENSE_LEVEL <= 2  # Rounds 1-2 explain every block. Never do this in production.
    if decision.action == "allow":
        return password_verdict(cred)
    if decision.action == "block":
        if not leaky:
            return password_verdict("wrong_password")  # deceptive: looks like a typo
        body = {"error": "blocked", "score": decision.score, "reasons": decision.reasons()}
        if decision.veto_layer:
            body["layer"] = decision.veto_layer
        return jsonify(body), 403
    body = ladder.issue(counters, sid, decision.action, username, cred)
    if decision.action == "pow":
        if leaky:
            body.update(score=decision.score, reasons=decision.reasons())
        return jsonify(body), 403
    return jsonify(body), 202


@app.after_request
def timing(response):
    if "pipeline_ms" in g:
        response.headers["Server-Timing"] = f"pipeline;dur={g.pipeline_ms:.3f}"
    return response


@app.route("/")
def index():
    return render_template_string(INDEX_HTML, level=DEFENSE_LEVEL)


@app.route("/login", methods=["GET"])
def login_page():
    resp = make_response(render_template_string(LOGIN_HTML, level=DEFENSE_LEVEL))
    resp.set_cookie("sid", session_id(), httponly=True, samesite="Lax")
    return resp


@app.route("/telemetry", methods=["POST"])
def collect():
    sid = session_id()
    blob = request.get_json(silent=True) or {}
    counters.put(json.dumps(telemetry.features(blob)), "tel", sid, ttl=1800)
    resp = make_response("", 204)
    resp.set_cookie("sid", sid, httponly=True, samesite="Lax")
    return resp


@app.route("/login", methods=["POST"])
def login():
    sid = session_id()
    edge_info, ja4, headers, lab_actor = edge.from_request(request)

    if "X-PoW" in request.headers:  # second leg of a pow challenge
        parked = ladder.resolve(counters, sid, pow_nonce=request.headers["X-PoW"])
        if parked is None:
            return jsonify({"error": "challenge failed"}), 403
        log({"type": "resolve", "sid": sid, "actor": lab_actor, "via": "pow"})
        return password_verdict(parked["cred"])

    username = request.form.get("username", "")
    raw = counters.fetch("tel", sid)
    ctx = Context(edge=edge_info, ja4=ja4, headers=headers,
                  ua=parse_ua(request.headers.get("User-Agent", "")),
                  telemetry=json.loads(raw) if raw else None,
                  form=request.form, counters=counters, sid=sid)
    decision = evaluate(ctx, DEFENSE_LEVEL)
    g.pipeline_ms = decision.ms

    # The password is checked for every attempt, even ones we will block:
    # the campaign layer needs the outcome, and the timing must not differ.
    cred = users.check(USERS, username, request.form.get("password", ""))
    if DEFENSE_LEVEL >= 4:
        campaign.record(ctx, failed=cred != "valid")

    log({"type": "decision", "sid": sid, "actor": lab_actor, "ip": edge_info["ip"],
         "pool": edge_info.get("pool"), "cluster": campaign.cluster_key(ctx),
         "signals": decision.signals, "score": decision.score, "action": decision.action,
         "veto_layer": decision.veto_layer, "cred": cred, "ms": round(decision.ms, 3)})
    return respond(decision, cred, sid, username)


@app.route("/login/verify", methods=["POST"])
def verify():
    sid = session_id()
    _, _, _, lab_actor = edge.from_request(request)
    code = (request.get_json(silent=True) or {}).get("code", "")
    parked = ladder.resolve(counters, sid, code=code)
    if parked is None:
        return jsonify({"error": "Invalid or expired code"}), 401
    log({"type": "resolve", "sid": sid, "actor": lab_actor, "via": "step_up"})
    return password_verdict(parked["cred"])


@app.route("/lab/status")
def lab_status():
    return jsonify({"level": DEFENSE_LEVEL, "store": STORE_URL.split(":")[0], "log": LOG_PATH})


@app.route("/lab/reset", methods=["POST"])
def lab_reset():
    deleted = counters.reset()
    with _log_lock:
        open(LOG_PATH, "w").close()
    return jsonify({"deleted_keys": deleted})


@app.route("/lab/mailbox/<path:user>")
def lab_mailbox(user):
    return jsonify({"user": user, "code": counters.fetch("mailbox", user)})


INDEX_HTML = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Bot Workshop Store</title>
<style>body{font-family:system-ui;max-width:40rem;margin:3rem auto;padding:0 1rem}
code{background:#eee;padding:0 .3rem}</style></head>
<body><h1>Bot Workshop Store</h1>
<p>Defense level <code>{{ level }}</code> &middot; <a href="/login">Sign in</a></p></body></html>"""

LOGIN_HTML = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Sign in</title>
<style>body{font-family:system-ui;max-width:28rem;margin:3rem auto;padding:0 1rem}
label{display:block;margin:.8rem 0}input{width:100%;padding:.4rem}
.hp{position:absolute;left:-9999px}pre{background:#f4f4f4;padding:.6rem;white-space:pre-wrap}</style>
</head><body>
<h1>Sign in</h1><p>Defense level <code>{{ level }}</code>. Try <code>user000@example.test</code>.</p>
<form id="f">
  <label>Email <input name="username" autocomplete="username"></label>
  <label>Password <input name="password" type="password" autocomplete="current-password"></label>
  <div class="hp" aria-hidden="true"><label>Website <input name="website" tabindex="-1" autocomplete="off"></label></div>
  <button>Sign in</button>
</form>
<pre id="out"></pre>
<script>
// The collector: a few lines of what W2 Ch2-4 built properly
const t0 = performance.now(), mouse = [], keys = [], down = {};
let pointerType = "mouse";
const now = () => Math.round(performance.now() - t0);
addEventListener("pointermove", e => { if (mouse.length < 300) mouse.push([now(), e.clientX, e.clientY]); });
addEventListener("pointerdown", e => { pointerType = e.pointerType; });
addEventListener("keydown", e => { down[e.code] = now(); });
addEventListener("keyup", e => { if (e.code in down) { keys.push([down[e.code], now()]); delete down[e.code]; } });
function canvasHash() {
  const c = document.createElement("canvas"), x = c.getContext("2d");
  x.font = "16px Arial"; x.fillStyle = "#f60"; x.fillRect(10, 10, 100, 30);
  x.fillStyle = "#069"; x.fillText("antibot w2ch8", 2, 15);
  return c.toDataURL().slice(-48);
}
function renderer() {
  try { const g = document.createElement("canvas").getContext("webgl");
        const d = g.getExtension("WEBGL_debug_renderer_info");
        return g.getParameter(d ? d.UNMASKED_RENDERER_WEBGL : g.RENDERER); } catch (e) { return ""; }
}
async function sendTelemetry() {
  const fp = { platform: navigator.platform, webgl_renderer: renderer(), canvas: canvasHash(),
    canvas2: canvasHash(), screen: screen.width + "x" + screen.height,
    timezone: Intl.DateTimeFormat().resolvedOptions().timeZone, languages: navigator.languages,
    webdriver: navigator.webdriver, cdp: false, hardware_concurrency: navigator.hardwareConcurrency };
  await fetch("/telemetry", { method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ fp, behavior: { mouse, keys, pointer_type: pointerType } }) });
}
function zeroBits(b) { let n = 0; for (const x of b) { if (x === 0) { n += 8; continue; }
  return n + Math.clz32(x) - 24; } return n; }
async function solve(p) {
  const enc = new TextEncoder();
  for (let n = 0; ; n++) {
    const d = new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(p.prefix + ":" + n)));
    if (zeroBits(d) >= p.bits) return String(n);
  }
}
const out = document.getElementById("out"), form = document.getElementById("f");
form.addEventListener("submit", async e => {
  e.preventDefault();
  await sendTelemetry();
  const body = new URLSearchParams(new FormData(form));
  let r = await fetch("/login", { method: "POST", body }), j = await r.json();
  if (j.action === "challenge") {
    out.textContent = "Solving a proof-of-work challenge...";
    const t = performance.now(), nonce = await solve(j.pow);
    out.textContent = `Solved in ${Math.round(performance.now() - t)} ms\\n`;
    r = await fetch("/login", { method: "POST", headers: { "X-PoW": nonce }, body }); j = await r.json();
  } else if (j.action === "verify") {
    const code = prompt("We emailed you a code (read it at /lab/mailbox/<your email>):");
    r = await fetch("/login/verify", { method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ code }) }); j = await r.json();
  }
  out.textContent += r.status + " " + JSON.stringify(j, null, 2);
});
</script></body></html>"""


if __name__ == "__main__":
    print(f" * Defense level {DEFENSE_LEVEL} · store {STORE_URL} · log {LOG_PATH}")
    # PORT: macOS AirPlay Receiver squats on 5000; use e.g. PORT=5050
    app.run(debug=True, port=int(os.environ.get("PORT", "5000")), threaded=True)
