"""
Chapter 5 — Debrief: fingerprints as an aggregation key (Section 5.8)

A JA4 alone rarely justifies a block once impersonation is in play: the
curl_cffi bot and every real Chrome share t13d1516h2_8daaf6152771. What still
works is grouping traffic by fingerprint and asking how each group behaves.
Cloudflare's "JA4 Signals" (2024) does this globally with hourly ratios per
JA4: share of browser-like traffic, cache hits, HTTP/2-3 use, request volume
rank. This report does the small, local version from our request log:

    per (JA4 a+b, HTTP/2 core)   requests, distinct UAs, share of /api/ calls,
                                 share of page loads, share blocked

Read it like a defender:
  - a cluster with many User-Agents but one TLS stack is rotating UAs;
  - a "browser" cluster that never loads a page and only hits /api/ is a script;
  - a cluster you've never seen that suddenly carries 50% of /login is a
    campaign, whatever its fingerprint says.

Run (same DATABASE_URL as the demo site):
    python tools/fingerprint_report.py
    python tools/fingerprint_report.py --minutes 30
"""

import argparse
import os
from collections import defaultdict
from datetime import datetime, timedelta, timezone

from sqlalchemy import create_engine, text

DATABASE_URL = os.environ.get("DATABASE_URL", "postgresql+psycopg://workshop:workshop@localhost:5432/shop")
QUERY = text("SELECT ja4, h2, ua_string, path, verdict FROM tls_log WHERE timestamp >= :since")


def h2_core(h2):
    if not h2:
        return "http/1.1"
    parts = h2.split("|")
    return f"{parts[0]}|{parts[1]}|{parts[3]}" if len(parts) == 4 else h2


def main():
    parser = argparse.ArgumentParser(description="Per-fingerprint traffic signals")
    parser.add_argument("--minutes", type=int, default=240)
    args = parser.parse_args()

    url = DATABASE_URL
    if DATABASE_URL.startswith("sqlite:///") and not DATABASE_URL.startswith("sqlite:////"):
        # Flask-SQLAlchemy puts relative SQLite paths in Flask's instance folder,
        # which is lab/instance/ when the app is started as `python demo_site/app.py`
        name = DATABASE_URL[len("sqlite:///"):]
        lab = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
        for folder in ("instance", os.path.join("demo_site", "instance")):
            candidate = os.path.join(lab, folder, name)
            if os.path.exists(candidate):
                url = "sqlite:///" + os.path.abspath(candidate)
                break
    since = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(minutes=args.minutes)
    with create_engine(url).connect() as conn:
        rows = conn.execute(QUERY, {"since": since}).fetchall()

    clusters = defaultdict(list)
    for ja4, h2, ua, path, verdict in rows:
        if path in ("/tls-check", "/tls-logs"):
            continue
        key = (ja4.rsplit("_", 1)[0] if ja4 else "no-edge", h2_core(h2))
        clusters[key].append((ua, path, verdict))

    print(f"Last {args.minutes} min, {sum(map(len, clusters.values()))} requests, {len(clusters)} clusters\n")
    print(f"{'JA4 a+b':<24} {'reqs':>5} {'UAs':>4} {'api%':>5} {'page%':>6} {'blocked%':>9}  HTTP/2 core")
    for (ja4_ab, h2), reqs in sorted(clusters.items(), key=lambda kv: -len(kv[1])):
        n = len(reqs)
        uas = len({ua for ua, _, _ in reqs})
        api = sum(p.startswith("/api/") and p != "/api/engine" for _, p, _ in reqs) / n
        page = sum(p == "/" for _, p, _ in reqs) / n
        blocked = sum(v == "bot" for _, _, v in reqs) / n
        print(f"{ja4_ab:<24} {n:>5} {uas:>4} {api:>5.0%} {page:>6.0%} {blocked:>9.0%}  {h2[:60]}")


if __name__ == "__main__":
    main()
