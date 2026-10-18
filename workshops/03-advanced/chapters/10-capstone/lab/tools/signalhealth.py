"""
Signal health: the console version of the Grafana board (W3 Ch4, for the capstone).

Operating a stack is not just scoring traffic; it is watching whether each signal is still firing. A layer that
goes quiet has either been bypassed or has drifted, and you want to know before the attacker tells you. This tool
reads the decision log (/lab/decisions) and prints:

    outcomes        what the store did, by phase (request, the drop, the login)
    layer triggers  how often each layer, L0 to L7, contributed a signal (shadow signals count: that is what shadow
                    mode is for), and which layers were SILENT
    stream CV       the inter-request coefficient of variation of every session the streaming layer has seen, split by
                    who it was (the log knows; the defenses never do), so you can see the low-and-slow band
                    separate from the humans, and where REG_MAX_CV would have to sit

With the optional `prod` profile the same counts are scraped from /metrics by Prometheus and drawn in Grafana
(http://127.0.0.1:3000). In the debrief, run this during an attack window and ask of every silent layer: bypassed,
or drifted?

    python tools/signalhealth.py
    python tools/signalhealth.py --since 2026-10-15T09:00:00
"""

import argparse
import collections
import os
import statistics
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import labclient  # noqa: E402  (runs the labnet localhost guard)

from defenses import layers  # noqa: E402


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    ap.add_argument("--since", help="only decisions after this UTC time (ISO 8601)")
    ap.add_argument("--limit", type=int, default=5000)
    args = ap.parse_args()
    params = {"limit": args.limit}
    if args.since:
        params["since"] = args.since
    rows = labclient.admin("GET", "/lab/decisions", params=params)["items"]
    if not rows:
        print("No decisions recorded yet. Run an attack or tools/checkpoint.py first.")
        return 0
    print(f"=== Signal health over {len(rows)} decisions (level {rows[-1]['level']}) ===\n")

    print("Outcomes by phase")
    by_phase = collections.defaultdict(collections.Counter)
    for d in rows:
        by_phase[d["phase"]][d["outcome"]] += 1
    for phase, counts in sorted(by_phase.items()):
        print(f"  {phase:<22} {sum(counts.values()):>5}  |  " + " ".join(f"{k} {v}" for k, v in sorted(counts.items())))

    print("\nLayer trigger rate (decisions in which each layer contributed a signal; shadow signals included)")
    fired = collections.Counter()
    for d in rows:
        flags = [f for f in (d.get("signals") or "").split(",") + (d.get("shadow") or "").split(",") if f]
        for layer in {layers.layer_of(f) for f in flags}:
            fired[layer] += 1
    for layer in layers.LAYERS:
        n = fired.get(layer, 0)
        bar = "#" * int(round(30 * n / len(rows)))
        print(f"  {layer} {layers.LAYER_NAME[layer]:<20} {n:>5}/{len(rows)}  {bar}{'   <- silent' if n == 0 else ''}")

    kinds = {}
    for d in rows:
        kinds.setdefault(d["sid"], (d.get("actor") or "?").split(":")[0])
    try:
        sessions = labclient.admin("GET", "/lab/stream/all")["sessions"]
    except Exception:
        sessions = []
    cvs = collections.defaultdict(list)
    for s in sessions:
        if s["cv"] is not None and s["gaps"] >= 8:
            cvs[kinds.get(s["sid"], "?")].append(s["cv"])
    if cvs:
        print("\nStream: inter-request CV per session (sessions with 8+ gaps)")
        for kind, vals in sorted(cvs.items()):
            print(f"  {kind:<6} n={len(vals):>3}  min {min(vals):.3f}  median {statistics.median(vals):.3f}  max {max(vals):.3f}")
        print("  The regularity ceiling (REG_MAX_CV) must sit above every bot's CV and below every person's.")

    print("\nA layer that is silent during an attack window is a finding: it was bypassed, or it has drifted.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
