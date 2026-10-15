"""
Live interception demo: a mitmproxy addon (Round 1 and 2, optional).

This is the real-tool version of Round 1, for the live demo. It logs every /api/mobile/ call and pulls out the
attestation verdict and the bearer token, which is exactly what a reverse engineer does to learn an API.

Rules of engagement: point it at your OWN local store only. It refuses to record flows whose host is not this
machine (labnet.is_local). The lab serves plain HTTP on loopback, so there is no TLS to terminate and no proxy
CA to install; the certificate step of a real interception is what Round 1's pinning defends, and it is modelled
in attacks/round1_intercept.py. You need requirements-mitmproxy.txt for this demo (see the README).

Run (three terminals, from the lab folder):
    1.  PORT=5000 python demo_site/app.py
    2.  mitmdump --listen-host 127.0.0.1 --listen-port 8080 -s attacks/mitm_capture.py
    3.  drive the app THROUGH the proxy:
          DEMO_URL=http://127.0.0.1:5000 HTTP_PROXY=http://127.0.0.1:8080 NO_PROXY= python - <<'PY'
          import sys; sys.path[:0] = ["tools", "."]
          from mobile_sdk import MobileApp
          a = MobileApp("bot:demo")
          a.register({"email": "demo@mail.example", "password": "demopass1"})
          print(a.buy().status_code)
          PY

Captured calls land in attacks/data/captured_calls.jsonl (gitignored). With certificate pinning implemented
in the app, a pinned client would REFUSE to connect through a proxy that presents its own certificate: that is
the whole point of Round 1's defense.
"""

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))  # lab root: labnet.py
from labnet import is_local  # noqa: E402

try:
    from mitmproxy import http
except ImportError:  # importable without mitmproxy for py_compile / docs
    http = None

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "captured_calls.jsonl")


def response(flow):
    if not is_local(flow.request.pretty_url):
        return  # rules of engagement: never record third-party traffic
    if "/api/mobile/" not in flow.request.path:
        return
    record = {
        "method": flow.request.method,
        "path": flow.request.path,
        "x_attest": flow.request.headers.get("X-Attest"),
        "authorization": flow.request.headers.get("Authorization"),
        "req_body": flow.request.get_text(strict=False),
        "status": flow.response.status_code,
        "resp_body": flow.response.get_text(strict=False)[:500],
    }
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "a") as f:
        f.write(json.dumps(record) + "\n")
    print(f"[+] captured {record['method']} {record['path']} "
          f"(attest={'yes' if record['x_attest'] else 'no'})")


addons = []  # mitmdump picks up module-level functions; nothing to instantiate
