"""
W3 Ch3 — Shared attacker helpers (rules of engagement built in)

Every attack and the legitimate-traffic simulator build *events*: dicts that
become one entry in the Redis Stream. Nothing here touches the network by
default — the unit of study in this chapter is the event log, so the generators
write synthetic events straight into your local stream. The optional --live
mode (see each script) replays the same events as real HTTP against the local
Flask site, and only then does the localhost guard apply.

Rules, enforced here:
  - target() only returns http(s)://localhost / 127.0.0.1 / ::1 and exits on
    anything else. These scripts never point at a site you do not own.
  - Every IP is from a documentation range (RFC 5737: 192.0.2.0/24,
    198.51.100.0/24, 203.0.113.0/24). No real proxy, no proxy list, no third
    party. Humans and bots use disjoint ranges so the ground truth is clean.
  - Usernames, sessions and timings are synthetic and seeded, so every run is
    reproducible.

The `actor` field on each event is ground truth ("human:..." or "bot:..."). It
is the one thing only the scoreboard is allowed to read; the detectors never
see it.
"""

import os
import sys
from urllib.parse import urlparse

LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}

# A fixed base time so windows, sketch buckets and CVs are identical every run.
BASE_TS = 1_700_000_000.0

HUMAN_NET = "203.0.113."       # TEST-NET-3, legitimate customers
BOT_NET_A = "198.51.100."      # TEST-NET-2, bot IPs
BOT_NET_B = "192.0.2."         # TEST-NET-1, more bot IPs

ASSET_MARKERS = ("/static/", ".js", ".css", ".png", ".woff", ".ico")


def target():
    url = os.environ.get("DEMO_URL", "http://localhost:5000").rstrip("/")
    host = urlparse(url).hostname
    if host not in LOCAL_HOSTS:
        sys.exit(f"🛑 Refusing to attack {host!r}. Lab attacks only run against your own local demo store.")
    return url


def make_event(ts, sid, ip, path, status=200, method="GET", user="", actor="", ua="python-lab"):
    """Build one HTTP event for the stream. ts is event time (epoch seconds)."""
    is_asset = any(m in path.lower() for m in ASSET_MARKERS)
    return {
        "ts": round(float(ts), 3), "sid": sid, "ip": ip, "path": path,
        "method": method, "status": str(status), "user": user,
        "ua": ua, "is_asset": "1" if is_asset else "0", "actor": actor,
    }


def bot_ip(index):
    """Map a bot index to a distinct documentation IP across two /24 ranges."""
    if index < 254:
        return f"{BOT_NET_A}{index + 1}"
    return f"{BOT_NET_B}{(index - 254) % 254 + 1}"


def replay_live(events):
    """Optional --live mode: replay generated events as real HTTP to the local site."""
    import httpx
    base = target()
    with httpx.Client(base_url=base, timeout=5.0) as c:
        for e in sorted(events, key=lambda x: float(x["ts"])):
            data = None
            if e["method"] == "POST":
                pw = "wrong" if str(e["status"]) in ("401", "403") else "correct"
                data = {"email": e.get("user", ""), "password": pw}
            try:
                c.request(e["method"], e["path"], data=data, cookies={"sid": e["sid"]})
            except Exception:
                pass


def deliver(events, summary_line):
    """Write events to the local stream, or (with --live) replay them over HTTP."""
    if "--live" in sys.argv:
        replay_live(events)
        print(f"[live] replayed {len(events)} events to {target()} "
              f"(watch /admin/verdicts)")
        return
    import store
    import stream
    r = store.connect()
    for e in events:
        stream.emit(r, e)
    print(summary_line)
