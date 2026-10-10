"""
Chapter 4 (W3) Lab: the demo store's login, in production for five weeks

The W2 Ch8 pipeline is live: eight sensors, a correlation layer, one risk
score and a response ladder, plus the W2 Ch7 model as a sensor with three
roles (prod, shadow, canary). There is no DEFENSE_LEVEL any more. What
changes from round to round is *operational state*, all of it hot:

    data/ops_config.json       weights, thresholds, campaign switch, TTL, canary %   (tools/configure.py, contain.py, canary.py)
    data/world_updates.json    what the data refresh learned since the snapshot     (tools/refresh_corpus.py)
    models/manifest.json       which model version holds which role                 (tools/registry.py)
    data/labels.jsonl          what an analyst said about sessions                  (tools/label.py)

Start it once and leave it running for the whole chapter:

    REDIS_URL=memory:// python app.py        # or docker compose up -d --wait, then python app.py

Flow of one login, the same for simulated humans and bots:

    GET  /login        form + collector script; sets the `sid` session cookie
    POST /telemetry    collector posts fingerprint + behaviour trace
    POST /login        pipeline scores it -> allow | pow | step_up | block
    POST /login        again with X-PoW: <nonce>      (after a pow challenge)
    POST /login/verify {"code": ...}                   (after a step-up)

Observability:
    GET  /metrics       Prometheus exposition (defenses/metrics.py)
    GET  /lab/config    effective config, model roles, corpus age, lab clock

Lab-only endpoints (localhost, never in production):
    GET  /lab/status            store, log path, last lab clock seen
    POST /lab/new-week          expire the windowed counters (a new week starts)
    POST /lab/reset             back to the start of the chapter: counters, log,
                                config, refresh, labels, models, truth
    GET  /lab/mailbox/<user>    the user's inbox; only the simulated *real*
                                users may read it (tools/population.py)

Every decision is appended to ../decision_log.jsonl (schema: tools/report.py).
"""

import glob
import json
import os
import secrets
import sys
import threading
import time

from flask import Flask, Response, g, jsonify, make_response, render_template_string, request

HERE = os.path.dirname(os.path.abspath(__file__))
LAB = os.path.join(HERE, "..")
sys.path.insert(0, os.path.join(LAB, "defenses"))

import allowlist  # noqa: E402
import campaign  # noqa: E402
import config  # noqa: E402
import corpus  # noqa: E402
import drift  # noqa: E402
import edge  # noqa: E402
import features  # noqa: E402
import ladder  # noqa: E402
import metrics  # noqa: E402
import registry  # noqa: E402
import store  # noqa: E402
import telemetry  # noqa: E402
import users  # noqa: E402
from pipeline import Context, evaluate  # noqa: E402
from sensors.headers import parse_ua  # noqa: E402

LOG_PATH = os.environ.get("DECISION_LOG", os.path.join(LAB, "decision_log.jsonl"))
STORE_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
DATA_DIR = os.path.join(LAB, "data")

app = Flask(__name__)
counters = store.Counters(store.connect(STORE_URL))
USERS = users.build()
_log_lock = threading.Lock()
_clock = {"week": 0, "clock": 0}


def log(entry):
    entry.update(ts=round(time.time(), 3))
    with _log_lock, open(LOG_PATH, "a") as f:
        f.write(json.dumps(entry) + "\n")


def session_id():
    return request.cookies.get("sid") or secrets.token_hex(12)


def password_verdict(cred):
    """The honest answer. A deceptive block must be byte-identical to the 401."""
    if cred == "valid":
        return jsonify({"ok": True}), 200
    return jsonify({"error": "Invalid credentials"}), 401


def respond(action, cred, sid, username):
    """Turn an action into a response. Blocks are deceptive (W2 Ch8 Round 3):
    the client learns nothing it could not learn from a typo."""
    if action == "allow":
        return password_verdict(cred)
    if action == "block":
        return password_verdict("wrong_password")
    body = ladder.issue(counters, sid, action, username, cred)
    return jsonify(body), 403 if action == "pow" else 202


@app.after_request
def timing(response):
    if "pipeline_ms" in g:
        response.headers["Server-Timing"] = f"pipeline;dur={g.pipeline_ms:.3f}"
    return response


@app.route("/")
def index():
    return render_template_string(INDEX_HTML, week=_clock["week"])


@app.route("/login", methods=["GET"])
def login_page():
    resp = make_response(render_template_string(LOGIN_HTML))
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
    edge_info, ja4, headers, lab = edge.from_request(request)
    if lab["clock"]:
        _clock.update(lab)

    if "X-PoW" in request.headers:  # second leg of a pow challenge
        parked = ladder.resolve(counters, sid, pow_nonce=request.headers["X-PoW"])
        if parked is None:
            return jsonify({"error": "challenge failed"}), 403
        log({"type": "resolve", "sid": sid, "actor": lab["actor"], "via": "pow", "week": lab["week"]})
        return password_verdict(parked["cred"])

    username = request.form.get("username", "")
    raw = counters.fetch("tel", sid)
    ctx = Context(edge=edge_info, ja4=ja4, headers=headers,
                  ua=parse_ua(request.headers.get("User-Agent", "")),
                  telemetry=json.loads(raw) if raw else None,
                  form=request.form, counters=counters, sid=sid)
    cfg = config.effective(lab["clock"] or None)
    decision = evaluate(ctx, cfg)
    g.pipeline_ms = decision.ms
    known_good = allowlist.is_known_good(request.headers)
    action, suppressed = allowlist.enforce(decision, known_good)

    # The password is checked for every attempt, even ones we will block:
    # the campaign layer needs the outcome, and the timing must not differ.
    cred = users.check(USERS, username, request.form.get("password", ""))
    if cfg.get("campaign"):
        campaign.record(ctx, failed=cred != "valid")
    metrics.observe(decision, cred, known_good, decision.model)

    log({"type": "decision", "sid": sid, "actor": lab["actor"], "week": lab["week"], "clock": lab["clock"],
         "ip": edge_info["ip"], "pool": edge_info.get("pool"), "edge_type": edge_info.get("type", "unknown"),
         "cluster": campaign.cluster_key(ctx), "signals": decision.signals, "score": decision.score,
         "action": decision.action, "enforced": action, "known_good": known_good,
         "tel": features.telemetry_numbers(ctx.telemetry), "model": decision.model,
         "cred": cred, "ms": round(decision.ms, 3),
         "overrides": bool(cfg.get("weights") or cfg.get("block_at") or cfg.get("challenge_at")
                           or cfg.get("campaign"))})
    return respond(action, cred, sid, username)


@app.route("/login/verify", methods=["POST"])
def verify():
    sid = session_id()
    _, _, _, lab = edge.from_request(request)
    code = (request.get_json(silent=True) or {}).get("code", "")
    parked = ladder.resolve(counters, sid, code=code)
    if parked is None:
        return jsonify({"error": "Invalid or expired code"}), 401
    log({"type": "resolve", "sid": sid, "actor": lab["actor"], "via": "step_up", "week": lab["week"]})
    return password_verdict(parked["cred"])


@app.route("/metrics")
def prometheus_metrics():
    for corpus_name, age in drift.corpus_ages(_clock["week"] or 1).items():
        metrics.corpus_age.labels(corpus=corpus_name).set(age)
    body, content_type = metrics.render()
    return Response(body, mimetype=content_type)


@app.route("/lab/config")
def lab_config():
    return jsonify({"config": config.load(), "effective_now": config.effective(_clock["clock"] or None),
                    "roles": registry.load()["roles"], "corpus_updates": corpus.updates(),
                    "corpus_age_weeks": drift.corpus_ages(_clock["week"] or 1), "lab": _clock})


@app.route("/lab/status")
def lab_status():
    return jsonify({"store": STORE_URL.split(":")[0], "log": LOG_PATH, **_clock,
                    "prod_model": registry.load()["roles"].get("prod")})


@app.route("/lab/new-week", methods=["POST"])
def lab_new_week():
    return jsonify({"deleted_keys": counters.reset()})


@app.route("/lab/reset", methods=["POST"])
def lab_reset():
    deleted = counters.reset()
    with _log_lock:
        open(LOG_PATH, "w").close()
    config.clear()
    corpus.clear()
    for path in [os.path.join(DATA_DIR, "labels.jsonl"), os.path.join(DATA_DIR, "truth.jsonl"),
                 registry.MANIFEST] + glob.glob(os.path.join(registry.MODELS_DIR, "model_v*.txt")):
        if os.path.exists(path):
            os.remove(path)
    _clock.update(week=0, clock=0)
    return jsonify({"deleted_keys": deleted})


@app.route("/lab/mailbox/<path:user>")
def lab_mailbox(user):
    return jsonify({"user": user, "code": counters.fetch("mailbox", user)})


INDEX_HTML = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Bot Workshop Store</title>
<style>body{font-family:system-ui;max-width:40rem;margin:3rem auto;padding:0 1rem}
code{background:#eee;padding:0 .3rem}</style></head>
<body><h1>Bot Workshop Store</h1>
<p>Week <code>{{ week }}</code> of operations &middot; <a href="/login">Sign in</a> &middot; <a href="/metrics">/metrics</a> &middot; <a href="/lab/config">/lab/config</a></p></body></html>"""

LOGIN_HTML = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Sign in</title>
<style>body{font-family:system-ui;max-width:28rem;margin:3rem auto;padding:0 1rem}
label{display:block;margin:.8rem 0}input{width:100%;padding:.4rem}
.hp{position:absolute;left:-9999px}pre{background:#f4f4f4;padding:.6rem;white-space:pre-wrap}</style>
</head><body>
<h1>Sign in</h1><p>Try <code>user000@example.test</code>.</p>
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
  x.fillStyle = "#069"; x.fillText("antibot w3ch4", 2, 15);
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
    print(f" * W3 Ch4 store · store {STORE_URL} · log {LOG_PATH} · prod model {registry.load()['roles'].get('prod') or 'none'}")
    # PORT: macOS AirPlay Receiver squats on 5000; use e.g. PORT=5050
    app.run(debug=False, port=int(os.environ.get("PORT", "5000")), threaded=True)
