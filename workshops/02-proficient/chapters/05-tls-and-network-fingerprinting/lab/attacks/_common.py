"""
Shared plumbing for the W2 Ch5 attack scripts.

Rules of engagement, enforced in code:
  - Every script imports tools/labclient.py, which asks labnet.py (lab root) for DEMO_URL and
    refuses anything that is not this machine.
  - The TLS edge URL (TLS_EDGE_URL, default https://localhost:8443) goes through labnet.target(),
    so it must be local too, and these scripts refuse to skip the edge by talking to the store's
    own port: the whole point is that the store measures a handshake the attacker really made.
  - Source addresses are rented from data/world.json (`cloud_vm`, documentation ranges) and sent
    as X-Lab-Client-IP; fingerproxy forwards the lab headers like any other. No proxy is involved.
  - The lab's self-signed certificate (certs/tls.crt) is loaded as a CA where the client library
    supports it. Disabling verification is acceptable ONLY because the target is your own
    localhost edge.

Each script ends by printing one JSON line for tools/checkpoint.py:
    {"attempted": 10, "succeeded": 7, "statuses": {"200": 7, "403": 3}, "first_block": "ja4_denylist:library_ja4", ...}
The store's X-Lab-Signals header names the layer that fired: a teaching aid, never in production.
"""

import json
import os
import sys
from urllib.parse import urlparse

LAB = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(LAB, "tools"))
import labclient  # noqa: E402  (runs the labnet guard on import)
import labnet  # noqa: E402

EDGE_URL = labnet.target("TLS_EDGE_URL", "https://localhost:8443")
CA_FILE = os.path.join(LAB, "certs", "tls.crt")
PATH = "/api/products"
REQUESTS = 10

# What a W1 Ch4 graduate sends: every header copied from Chrome DevTools.
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
    "Referer": EDGE_URL + "/",
    "Accept-Encoding": "gzip, deflate, br, zstd",
    "Accept-Language": "en-US,en;q=0.9",
}


def require_edge(url=EDGE_URL):
    """Exit when the URL would skip the TLS edge (the store's own port)."""
    labnet.require_local(url, what="TLS_EDGE_URL")
    if urlparse(url).port == urlparse(labclient.BASE_URL).port or urlparse(url).scheme != "https":
        sys.exit(f"Refusing to target {url}: these attacks go through the TLS edge (python tools/edge.py, "
                 f"https://localhost:8443), never to the store's own port.")
    return url


require_edge()


def bot_ip():
    """The address this bot rents: a cloud VM from data/world.json."""
    return labclient.world_pool("cloud_vm")[3]


def lab_headers(actor):
    """The scoreboard label and the rented address, as headers fingerproxy forwards to the store."""
    return {"X-Lab-Client-IP": bot_ip(), "X-Lab-Actor": f"bot:{actor}"}


def result(status, headers, data=None):
    return {"status": status, "signals": headers.get("X-Lab-Signals", ""), "score": headers.get("X-Lab-Score", ""),
            "ok": status == 200, "n": len((data or {}).get("items", [])) if isinstance(data, dict) else 0}


def finish(results, **extra):
    """Print the human report, then the one JSON line the checkpoint reads. Returns the summary."""
    statuses = {}
    for r in results:
        statuses[str(r["status"])] = statuses.get(str(r["status"]), 0) + 1
    ok = [r for r in results if r["ok"]]
    blocked = next((r for r in results if r["status"] == 403), None)
    print(f"  Requests: {len(results)}   statuses: {statuses}")
    if ok:
        print(f"  Scraped {ok[0]['n']} products per call ({len(ok)}/{len(results)} succeeded)")
    if blocked:
        print(f"  Blocked (score {blocked['score']}): {blocked['signals']}")
    summary = {"attempted": len(results), "succeeded": len(ok), "statuses": statuses,
               "first_block": blocked["signals"] if blocked else "", **extra}
    print(json.dumps(summary))
    return summary
