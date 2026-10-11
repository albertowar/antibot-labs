"""
W3 Ch1 — Live interception demo: a mitmproxy addon (Round 1/2)

This is the real-tool version of Round 1, for the instructor demo. It logs every
/api/mobile/ call and pulls out the attestation token and bearer, which is
exactly what a reverse engineer does to learn an API.

Rules of engagement: point it at your OWN local store only. It refuses to record
flows whose host is not localhost.

Run (three terminals):
    1.  REDIS_URL=memory:// python demo_site/app.py
    2.  mitmdump --listen-port 8080 -s attacks/mitm_capture.py --ssl-insecure
    3.  drive the app THROUGH the proxy, e.g.:
          DEMO_URL=https://localhost:8443 \
          HTTPS_PROXY=http://127.0.0.1:8080 \
          python - <<'PY'
          from attacks.mobile_client import MobileApp
          a = MobileApp(); a.register({"email":"demo@mail.example","password":"demopass1","address":"1 Lab St"})
          print(a.buy().json())
          PY

Captured calls land in attacks/data/captured_calls.jsonl. With certificate
pinning implemented in the app, step 3 would REFUSE to connect through the
proxy — that is the whole point of Round 1's defense.
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
    with open(OUT, "a") as f:
        f.write(json.dumps(record) + "\n")
    print(f"[+] captured {record['method']} {record['path']} "
          f"(attest={'yes' if record['x_attest'] else 'no'})")


addons = []  # mitmdump picks up module-level functions; nothing to instantiate
