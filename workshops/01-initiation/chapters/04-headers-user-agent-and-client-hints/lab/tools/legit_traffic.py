"""
Chapter 4 — Legitimate Traffic Simulator (Section 4.7)

Measures the other half of every defense: how many REAL users it blocks.

Replays header profiles captured from real browsers (tools/profiles/*.json)
against the demo site, byte-for-byte and in their original header order, and
reports blocked (403) and "suspicious" verdicts. A defense that catches bots
but blocks these users has failed.

A profile is simply the JSON that /header-check returns. To add your own
browser: open http://localhost:5000/ then http://localhost:5000/header-check
(with DEFENSE_LEVEL=4, so Chromium includes its negotiated hints) and save the
page as tools/profiles/<name>.json. Or run tools/capture_profiles.py.

Trade-off: a replay is only as good as its capture. Profiles go stale as
browsers update, so re-capture them whenever you bump MIN_CHROME_MAJOR.

Run the demo site first, then:
    python tools/legit_traffic.py
"""

import glob
import http.client
import json
import os
from urllib.parse import urlparse

_url = urlparse(os.environ.get("DEMO_URL", "http://localhost:5000"))
HOST, PORT = _url.hostname, _url.port or 80
PROFILES_DIR = os.path.join(os.path.dirname(__file__), "profiles")
PATHS = ["/", "/api/products"]


def load_profiles():
    profiles = []
    for path in sorted(glob.glob(os.path.join(PROFILES_DIR, "*.json"))):
        with open(path) as f:
            data = json.load(f)
        data.setdefault("name", os.path.splitext(os.path.basename(path))[0])
        profiles.append(data)
    return profiles


def replay(headers, path):
    """Send `headers` exactly as captured (same names, values and order)."""
    conn = http.client.HTTPConnection(HOST, PORT, timeout=5)
    conn.putrequest("GET", path, skip_host=True, skip_accept_encoding=True)
    for name, value in headers:
        if name.lower() == "host":
            value = f"{HOST}:{PORT}"
        conn.putheader(name, value)
    conn.endheaders()
    response = conn.getresponse()
    body = response.read()
    timing = response.getheader("Server-Timing", "")
    conn.close()
    score_ms = float(timing.split("dur=")[1]) if "dur=" in timing else None
    return response.status, body, score_ms


def run():
    """Replay every profile against every path. Returns one result per request."""
    results = []
    for profile in load_profiles():
        headers = profile["headers_received"]
        _, body, _ = replay(headers, "/header-check")
        check = json.loads(body)
        for path in PATHS:
            status, _, score_ms = replay(headers, path)
            results.append({
                "profile": profile["name"], "path": path, "status": status,
                "verdict": check["verdict"], "score": check["score"],
                "reasons": check["reasons"], "score_ms": score_ms,
            })
    return results


if __name__ == '__main__':
    results = run()
    if not results:
        print(f"No profiles found in {PROFILES_DIR}")
        raise SystemExit(1)
    print("=== Legitimate users (replayed real-browser profiles) ===")
    for r in results:
        mark = "✅" if r["status"] == 200 and r["verdict"] == "clean" else "❌"
        print(f"  {mark} {r['profile']:<28} GET {r['path']:<14} {r['status']}  "
              f"verdict={r['verdict']} score={r['score']}")
        for reason in r["reasons"]:
            print(f"       - {reason}")
    blocked = sum(r["status"] == 403 for r in results)
    print(f"\n  False positives: {blocked}/{len(results)} requests blocked")
