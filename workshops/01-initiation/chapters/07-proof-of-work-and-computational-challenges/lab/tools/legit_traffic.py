"""
Chapter 7 — Simulated real users (Section 7.7, "Measuring both sides")

Five users browse three catalog pages each. Every one of them solves the
same challenge a bot would, but each has a different *device*, and the
device decides what the puzzle costs them in seconds:

  desktop           a laptop browser, 4 workers          DESKTOP_MHS (default 4.0 MH/s)
  mid_phone         a mid-range Android phone            DESKTOP_MHS / 4
  low_end_phone     a 5-year-old budget phone            DESKTOP_MHS / 16
  no_js_reader      JavaScript off (or a text browser)   cannot solve at all
  cgnat_neighbour   a budget phone behind carrier NAT,   DESKTOP_MHS / 16
                    sharing 100.64.0.7 with ~150 other
                    requests a minute from the neighbours

The phone rates are assumptions (ratios, not measurements). Replace them
with your own: run /pow-bench on your laptop and your phone, then
    DESKTOP_MHS=<laptop MH/s> python tools/legit_traffic.py

How latency is reported: the server tells each user its difficulty; the
user's wait is hashes ÷ device rate. Because solving is geometric, we
report the distribution for that device, not one lucky draw:
  p50 / p95 wait and the share of users who would give up after
  PATIENCE_S seconds (P[hashes > rate × patience]).

The simulator still solves every challenge for real (on all cores of your
laptop), so every pass and every page is genuinely checked by the server.

Run:
    python tools/legit_traffic.py
"""

import math
import os
import re
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "attacks"))
from _common import Tally, client, close_pool, is_pow_gate, reasons, solve_parallel  # noqa: E402
from pow_core import hashes_at_percentile  # noqa: E402

DESKTOP_MHS = float(os.environ.get("DESKTOP_MHS", "4.0"))
PATIENCE_S = 5.0
CGNAT_BACKGROUND = 150  # requests from the neighbours behind the same CGNAT address

# name, simulated IP, hashes per second (0 = no JavaScript), background requests
PROFILES = [
    ("desktop", "198.51.100.10", DESKTOP_MHS * 1e6, 0),
    ("mid_phone", "198.51.100.20", DESKTOP_MHS / 4 * 1e6, 0),
    ("low_end_phone", "198.51.100.30", DESKTOP_MHS / 16 * 1e6, 0),
    ("no_js_reader", "198.51.100.40", 0, 0),
    ("cgnat_neighbour", "100.64.0.7", DESKTOP_MHS / 16 * 1e6, CGNAT_BACKGROUND),
]
PAGES = [1, 2, 3]


def server_timing(r):
    """Parse 'pow;dur=0.123, store;desc="2 ops"' into (ms, ops)."""
    h = r.headers.get("Server-Timing", "")
    dur = re.search(r"pow;dur=([\d.]+)", h)
    ops = re.search(r'store;desc="(\d+) ops"', h)
    return (float(dur.group(1)) if dur else None, int(ops.group(1)) if ops else None)


def browse(name, ip, rate, background):
    """One user's visit. Returns a result row."""
    row = {"profile": name, "blocked": False, "bits": None, "p50_s": 0.0, "p95_s": 0.0,
           "give_up": 0.0, "pages_ok": 0, "reasons": [], "gate_ms": [], "verify_ms": [],
           "ops": []}
    with client(ip, user_agent=f"Mozilla/5.0 (lab {name})") as c:
        for _ in range(background):
            c.get("/")
        c.get("/")
        for page in PAGES:
            r = c.get("/api/products", params={"page": page})
            if is_pow_gate(r):
                if rate == 0:
                    row["blocked"], row["reasons"] = True, reasons(r)
                    break
                challenge = c.get("/pow/challenge").json()
                bits = int(challenge["difficulty"])
                row["bits"] = bits
                row["p50_s"] = hashes_at_percentile(bits, .5) / rate
                row["p95_s"] = hashes_at_percentile(bits, .95) / rate
                row["give_up"] = math.exp(-rate * PATIENCE_S / 2 ** bits)
                counter = solve_parallel(challenge, Tally(name, wanted=1))
                v = c.post("/pow/verify", json={"challenge": challenge, "counter": counter})
                row["verify_ms"].append(server_timing(v)[0])
                r = c.get("/api/products", params={"page": page})
            if r.status_code != 200:
                row["blocked"], row["reasons"] = True, reasons(r)
                break
            row["pages_ok"] += 1
            ms, ops = server_timing(r)
            if ms is not None:
                row["gate_ms"].append(ms)
                row["ops"].append(ops)
    return row


def run():
    """Browse once per profile; return one row per profile (used by tools/checkpoint.py)."""
    try:
        return [browse(*p) for p in PROFILES]
    finally:
        close_pool()


def describe(row):
    if row["blocked"]:
        return f"BLOCKED: {row['reasons']}"
    if row["bits"] is None:
        return f"{row['pages_ok']}/{len(PAGES)} pages, no challenge"
    return (f"{row['bits']} bits · wait p50 {row['p50_s']:.2f} s, p95 {row['p95_s']:.2f} s · "
            f"{row['give_up']:.0%} would give up")


if __name__ == "__main__":
    print(f"=== Real users (desktop {DESKTOP_MHS} MH/s, patience {PATIENCE_S:.0f} s) ===")
    rows = run()
    for row in rows:
        print(f"  {row['profile']:<16} {describe(row)}")
    blocked = sum(r["blocked"] for r in rows)
    print(f"\n  Blocked outright: {blocked}/{len(rows)} users")
