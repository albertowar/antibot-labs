"""The rest of the internet, on 127.0.0.1:5001.

Verifying a crawler means talking to things you do not run: the DNS, the operator's
published range files, the agent's key directory. A lab cannot depend on them (they
change, they rate-limit, and we never send lab traffic at third parties), so this
one process plays all of them, deterministically, from tools/fixtures/:

    GET  /dns/ptr?ip=…                   reverse DNS (PTR) for an address
    GET  /dns/a?name=…                   forward DNS (A) for a name
    PUT  /hosting/ptr   {ip, name}       the attacker's hosting panel: set the PTR of
                                         an address in the attacker's own allocation
                                         (203.0.113.64/26, the hosting_asn pool)
    PUT  /hosting/a     {name, addrs}    …and the forward zone the attacker owns
    PUT  /hosting/directory {host, jwks, headers}
                                         publish a key directory for attacker.example
    GET  /ranges/<operator>/<file>.json  what the operators publish (live copies)
    GET  /dir/<host>/.well-known/http-message-signatures-directory
                                         an agent's signed JWK Set (chatgpt.com is built in)
    GET  /leak/stale?authority=h:p       a ChatGPT-User request signed 1 h ago with a 24 h
    GET  /leak/fresh?authority=h:p       window / signed now with a 60 s window, as a
                                         CDN log would have leaked them
    POST /reset                          forget everything the attacker published
    GET  /stats                          query counters (the defender's DNS bill)

Everything here is loopback only: the process binds 127.0.0.1, the hosting panel refuses
non-loopback callers, and `labnet.require_local_env("MOCK_URL")` refuses a MOCK_URL that is not
this machine. The store starts it on a thread by default (demo_site/ext/identity.py); run it by
hand with `python tools/mock_internet.py` and `MOCK_AUTOSTART=0` on the store to see the
two-process shape. Its keys come from tools/make_keys.py (generated, never committed).

Latency is simulated (DNS_LATENCY_MS, FETCH_LATENCY_MS) so caching shows up in the
scoreboard the way it does in production. The hosting endpoints only accept loopback
callers and only touch names and addresses the attacker "owns" in the fixture, so the
attack scripts can never rewrite a real operator's records, even here.
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

FIXTURES = os.path.join(HERE, "fixtures")
DNS_LATENCY_MS = float(os.environ.get("DNS_LATENCY_MS", "15"))
FETCH_LATENCY_MS = float(os.environ.get("FETCH_LATENCY_MS", "30"))
ATTACKER_NET = ipaddress.ip_network("203.0.113.64/26")      # data/world.json pool hosting_asn
ATTACKER_ZONES = (".attacker-hosting.example", ".attacker.example", "attacker.example")
BUILTIN_AGENT = "chatgpt.com"

app = Flask(__name__)
_lock = threading.Lock()

with open(os.path.join(FIXTURES, "dns_zones.json")) as fh:
    ZONES = json.load(fh)
PATTERNS = {ipaddress.ip_network(k): v for k, v in ZONES["patterns"].items() if not k.startswith("_")}
AGENT_KEY = make_keys.load(BUILTIN_AGENT)       # generated on first use, never committed
AGENT_PRIV = httpsig.load_private(AGENT_KEY["seed_hex"])

state = {"ptr": {}, "a": {}, "directories": {}, "stats": {"ptr": 0, "a": 0, "ranges": 0, "dir": 0}}


def _loopback_only():
    if not ipaddress.ip_address(request.remote_addr or "0.0.0.0").is_loopback:
        abort(403)


def _sleep(ms: float):
    if ms > 0:
        time.sleep(ms / 1000)


# ------------------------------------------------------------------- DNS

def ptr_names(ip: str) -> list[str]:
    if ip in state["ptr"]:
        return state["ptr"][ip]
    if ip in ZONES["ptr"]:
        return ZONES["ptr"][ip]
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return []
    for net, pattern in PATTERNS.items():
        if addr in net:
            return [pattern.format(d=ip.replace(".", "-"))]
    return []


def a_addrs(name: str) -> list[str]:
    name = name.lower().rstrip(".")
    if name in state["a"]:
        return state["a"][name]
    if name in ZONES["a"]:
        return ZONES["a"][name]
    # Names generated from a pattern resolve back to the address they were made from.
    for net, pattern in PATTERNS.items():
        prefix, suffix = pattern.split("{d}")
        if name.startswith(prefix) and name.endswith(suffix):
            middle = name[len(prefix):len(name) - len(suffix)]
            candidate = middle.replace("-", ".")
            try:
                if ipaddress.ip_address(candidate) in net:
                    return [candidate]
            except ValueError:
                pass
    return []


@app.get("/dns/ptr")
def dns_ptr():
    _sleep(DNS_LATENCY_MS)
    state["stats"]["ptr"] += 1
    return jsonify({"ip": request.args.get("ip", ""), "names": ptr_names(request.args.get("ip", ""))})


@app.get("/dns/a")
def dns_a():
    _sleep(DNS_LATENCY_MS)
    state["stats"]["a"] += 1
    return jsonify({"name": request.args.get("name", ""), "addrs": a_addrs(request.args.get("name", ""))})


# ------------------------------------------------- the attacker's hosting panel

@app.put("/hosting/ptr")
def hosting_ptr():
    _loopback_only()
    body = request.get_json(force=True)
    ip, name = body.get("ip", ""), body.get("name", "")
    if ipaddress.ip_address(ip) not in ATTACKER_NET:
        return jsonify({"error": "that address is not in your allocation"}), 403
    with _lock:
        state["ptr"][ip] = [name]
    return jsonify({"ok": True, "ip": ip, "ptr": [name]})


@app.put("/hosting/a")
def hosting_a():
    _loopback_only()
    body = request.get_json(force=True)
    name, addrs = body.get("name", "").lower(), body.get("addrs", [])
    if not name.endswith(ATTACKER_ZONES):
        return jsonify({"error": "you do not control that zone"}), 403
    with _lock:
        state["a"][name] = addrs
    return jsonify({"ok": True, "name": name, "addrs": addrs})


@app.put("/hosting/directory")
def hosting_directory():
    _loopback_only()
    body = request.get_json(force=True)
    host = body.get("host", "").lower()
    if host != "attacker.example":
        return jsonify({"error": "you only own attacker.example"}), 403
    with _lock:
        state["directories"][host] = {"jwks": body["jwks"], "headers": body.get("headers", {})}
    return jsonify({"ok": True, "url": f"/dir/{host}{httpsig.DIRECTORY_PATH}"})


# ------------------------------------------------------------- operators

@app.get("/ranges/<operator>/<path:name>")
def ranges(operator, name):
    _sleep(FETCH_LATENCY_MS)
    state["stats"]["ranges"] += 1
    path = os.path.join(FIXTURES, "ranges", operator, name)
    if not os.path.isfile(path) or not name.endswith(".json"):
        abort(404)
    with open(path) as fh:
        return Response(fh.read(), mimetype="application/json")


def _builtin_directory() -> dict:
    jwks = {"keys": [AGENT_KEY["jwk"]]}
    headers = httpsig.sign_directory(jwks, {AGENT_KEY["thumbprint"]: AGENT_PRIV}, BUILTIN_AGENT)
    return {"jwks": jwks, "headers": headers}


@app.get("/dir/<host>/.well-known/http-message-signatures-directory")
def directory(host):
    _sleep(FETCH_LATENCY_MS)
    state["stats"]["dir"] += 1
    host = host.lower()
    if host == BUILTIN_AGENT:
        entry = _builtin_directory()
    elif host in state["directories"]:
        entry = state["directories"][host]
    else:
        abort(404)
    resp = Response(json.dumps(entry["jwks"]), mimetype=httpsig.DIRECTORY_MEDIA_TYPE)
    for k, v in entry["headers"].items():
        if k.lower() in ("signature", "signature-input"):
            resp.headers[k] = v
    resp.headers["Cache-Control"] = "max-age=86400"
    return resp


# ------------------------------------------------------- the leaked requests

def _leak(authority: str, created: int, expires: int, note: str) -> dict:
    ctx = httpsig.MessageContext("GET", authority, "/product/p001",
                                 {"user-agent": "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; ChatGPT-User/1.0; +https://openai.com/bot"})
    h = httpsig.agent_headers(AGENT_PRIV, AGENT_KEY["thumbprint"], f"https://{BUILTIN_AGENT}", ctx,
                              created=created, expires=expires)
    return {"note": note, "method": "GET", "authority": authority, "path": "/product/p001",
            "headers": {"User-Agent": ctx.headers["user-agent"], **h}}


@app.get("/leak/stale")
def leak_stale():
    now = int(time.time())
    return jsonify(_leak(request.args.get("authority", "127.0.0.1:5000"), now - 3600, now + 23 * 3600,
                         "signed 1 h ago, 24 h window, covers @authority + signature-agent only"))


@app.get("/leak/fresh")
def leak_fresh():
    now = int(time.time())
    return jsonify(_leak(request.args.get("authority", "127.0.0.1:5000"), now, now + 60,
                         "signed just now, 60 s window, covers @authority + signature-agent only"))


# ------------------------------------------------------------------ admin

@app.post("/reset")
def reset():
    _loopback_only()
    with _lock:
        state["ptr"].clear()
        state["a"].clear()
        state["directories"].clear()
        for k in state["stats"]:
            state["stats"][k] = 0
    return jsonify({"ok": True})


@app.get("/stats")
def stats():
    return jsonify(state["stats"])


@app.get("/")
def index():
    return Response("<h1>mock internet</h1><p>DNS, operator range files and agent key directories "
                    "for the W4 Ch2 lab. See the module docstring for routes.</p>", mimetype="text/html")


if __name__ == "__main__":
    labnet.require_local_env("MOCK_URL")          # a MOCK_URL that is not this machine is refused
    port = int(os.environ.get("MOCK_PORT", "5001"))
    print(f"mock internet on http://127.0.0.1:{port}  (dns latency {DNS_LATENCY_MS} ms, fetch {FETCH_LATENCY_MS} ms)")
    app.run(host="127.0.0.1", port=port)
