"""
W2 Ch3, debrief: fingerprints as an aggregation key.

A JA4 alone rarely justifies a block once impersonation is in play: the curl_cffi bot and every
real Chrome share t13d1516h2_8daaf6152771. What still works is grouping traffic by fingerprint and
asking how each group behaves. Cloudflare's "JA4 Signals" (2024) does this globally with hourly
ratios per JA4: share of browser-like traffic, cache hits, HTTP/2-3 use, request volume rank. This
report does the small, local version from the store's decision log (every row carries the
fingerprint the TLS edge measured, see demo_site/ext/tls_edge.py):

    per (JA4 a+b, HTTP/2 core)   requests, distinct UAs, share of /api/ calls,
                                 share of page loads, share blocked

Read it like a defender:
  - a cluster with many User-Agents but one TLS stack is rotating UAs;
  - a "browser" cluster that never loads a page and only hits /api/ is a script;
  - a cluster you have never seen that suddenly carries 50% of /login is a campaign, whatever its
    fingerprint says.

Run (against the running store, DEMO_URL as for every tool):
    python tools/fingerprint_report.py
    python tools/fingerprint_report.py --minutes 30
"""

import argparse
from collections import defaultdict
from datetime import datetime, timedelta, timezone

import labclient


def cluster(items):
    clusters = defaultdict(list)
    for d in items:
        x = d.get("extra") or {}
        if d["path"].startswith("/lab/") or x.get("ja4") is None:
            continue
        key = (x.get("ja4_ab") or "no-fingerprint", x.get("h2_core") or "http/1.1", x.get("ja4_source") or "")
        clusters[key].append((x.get("ua", ""), d["path"], d["outcome"] == "blocked"))
    return clusters


def main():
    parser = argparse.ArgumentParser(description="Per-fingerprint traffic signals")
    parser.add_argument("--minutes", type=int, default=240)
    args = parser.parse_args()
    since = (datetime.now(timezone.utc) - timedelta(minutes=args.minutes)).strftime("%Y-%m-%dT%H:%M:%S")
    items = labclient.admin("GET", "/lab/decisions", params={"since": since, "limit": 5000})["items"]
    clusters = cluster(items)
    print(f"Last {args.minutes} min, {sum(map(len, clusters.values()))} requests, {len(clusters)} clusters\n")
    print(f"{'JA4 a+b':<24} {'src':<9} {'reqs':>5} {'UAs':>4} {'api%':>5} {'page%':>6} {'blocked%':>9}  HTTP/2 core")
    for (ja4_ab, h2, src), reqs in sorted(clusters.items(), key=lambda kv: -len(kv[1])):
        n = len(reqs)
        uas = len({ua for ua, _, _ in reqs})
        api = sum(p.startswith("/api/") and p != "/api/telemetry" for _, p, _ in reqs) / n
        page = sum(p == "/" for _, p, _ in reqs) / n
        blocked = sum(b for _, _, b in reqs) / n
        print(f"{ja4_ab:<24} {src:<9} {n:>5} {uas:>4} {api:>5.0%} {page:>6.0%} {blocked:>9.0%}  {h2[:60]}")


if __name__ == "__main__":
    main()
