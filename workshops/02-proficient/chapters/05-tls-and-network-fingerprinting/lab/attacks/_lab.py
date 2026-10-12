"""
Shared plumbing for the Chapter 5 attack scripts and tools.

- Target: DEMO_URL, default https://localhost:8443 (the TLS edge).
- Guardrail: refuses any host that isn't loopback, and refuses to skip the
  edge by talking to Flask directly. These scripts exist to train defenders
  against their own laptop. They never touch third-party sites or proxies.
- Trust: the lab's self-signed certificate (certs/tls.crt) is loaded as a CA
  where the client library supports it.
"""

import os
import sys
from urllib.parse import urlparse

LAB = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, LAB)  # lab root: labnet.py
import labnet  # noqa: E402

CA_FILE = os.path.join(LAB, "certs", "tls.crt")
BASE_URL = labnet.target("DEMO_URL", "https://localhost:8443")
ORIGIN_PORT = int(os.environ.get("PORT", "5000"))

# What a W1 Ch3 graduate sends: every header copied from Chrome DevTools.
# Update the major version to current stable before teaching.
CHROME_UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
             "(KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36")
CHROME_HEADERS = {
    "sec-ch-ua": '"Chromium";v="156", "Google Chrome";v="156", "Not.A/Brand";v="99"',
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": '"Linux"',
    "User-Agent": CHROME_UA,
    "Accept": "*/*",
    "Sec-Fetch-Site": "same-origin",
    "Sec-Fetch-Mode": "cors",
    "Sec-Fetch-Dest": "empty",
    "Referer": BASE_URL + "/",
    "Accept-Encoding": "gzip, deflate, br, zstd",
    "Accept-Language": "en-US,en;q=0.9",
}


def require_local(url: str) -> str:
    """Exit unless `url` points at this machine's TLS edge (labnet does the loopback check)."""
    labnet.require_local(url)
    if urlparse(url).port == ORIGIN_PORT:
        sys.exit(f"Refusing to target the origin on :{ORIGIN_PORT} directly. Go through the edge (:8443).")
    return url


require_local(BASE_URL)


def to_result(path, status, data):
    """Normalize one response for reporting and for tools/checkpoint.py."""
    data = data if isinstance(data, dict) else {}
    return {"path": path, "status": status, "data": data,
            "reasons": data.get("reasons", []) if status == 403 else []}


def report(results):
    statuses = [r["status"] for r in results]
    print(f"  Requests: {len(results)}   statuses: {sorted(set(statuses))}")
    ok = [r for r in results if r["status"] == 200]
    if ok:
        print(f"  Scraped: {[p['name'] for p in ok[0]['data'].get('products', [])]}  ({len(ok)}/{len(results)} succeeded)")
    blocked = [r for r in results if r["status"] == 403]
    if blocked:
        print(f"  Blocked (score {blocked[0]['data'].get('score')}):")
        for reason in blocked[0]["reasons"]:
            print(f"    - {reason}")
    print()
