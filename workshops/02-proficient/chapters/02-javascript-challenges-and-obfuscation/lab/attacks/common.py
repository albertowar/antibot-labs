"""
Chapter 2 — Shared helpers for the attack scripts.

Every attack scrapes the same thing: /api/products?page=1..PAGES (300 pages,
3,000 products). That makes the numbers comparable across rounds: pages
scraped, time taken, and how many browser solves it took.

Rules of engagement, enforced in code: attacks only run against localhost.
"""

import os
import statistics
import sys
import time
from urllib.parse import urlparse

import requests

BASE_URL = os.environ.get("DEMO_URL", "http://localhost:5000")
PAGES = int(os.environ.get("PAGES", "300"))
LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}

# What a scraper puts in User-Agent once it has been blocked for python-requests (W1 Ch4)
CHROME_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
             "(KHTML, like Gecko) Chrome/153.0.0.0 Safari/537.36")


def require_local(url=BASE_URL):
    host = urlparse(url).hostname
    if host not in LOCAL_HOSTS:
        sys.exit(f"Refusing to attack {host!r}: lab attacks only run against your own localhost demo site.")


# Server-Timing "gate" durations of requests that got through: what the defense
# costs the server on the happy path (HMAC check, plus a Redis INCR at level 5).
GATE_MS = []


def scrape(session, pages=PAGES, start=1):
    """
    Fetch product pages until done or blocked. Returns (pages_ok, reason, seconds),
    where reason is the server's 403 reason, or None if every page came back.
    """
    t0 = time.perf_counter()
    ok = 0
    for page in range(start, start + pages):
        r = session.get(f"{BASE_URL}/api/products", params={"page": page}, timeout=10)
        timing = r.headers.get("Server-Timing", "")
        if r.status_code == 200 and "dur=" in timing:
            GATE_MS.append(float(timing.split("dur=")[1]))
        if r.status_code != 200:
            try:
                reason = r.json().get("reason", f"HTTP {r.status_code}")
            except ValueError:
                reason = f"HTTP {r.status_code}"
            return ok, reason, time.perf_counter() - t0
        ok += 1
    return ok, None, time.perf_counter() - t0


def result(name, pages_ok, reason, seconds, solves=0, solve_seconds=0.0, pages_total=PAGES):
    gate_ms = statistics.median(GATE_MS) if GATE_MS else None
    GATE_MS.clear()
    return {"attack": name, "pages_ok": pages_ok, "pages_total": pages_total, "reason": reason,
            "seconds": seconds, "solves": solves, "solve_seconds": solve_seconds, "gate_ms": gate_ms}


def report(r):
    mark = "✅" if r["pages_ok"] == r["pages_total"] else "🛑"
    print(f"  {mark} scraped {r['pages_ok']}/{r['pages_total']} pages in {r['seconds']:.2f} s")
    if r["solves"]:
        print(f"     challenge solves: {r['solves']} ({r['solve_seconds']:.2f} s solving)")
    if r["reason"]:
        print(f"     blocked: {r['reason']}")
