"""
scoreboard.py — one screen: did data get out, and did we block anyone?

Reads the attacker collector and the demo store's report logs and prints the
round scoreboard. Run it after an attack + a legit_traffic pass.

Run:
    python tools/scoreboard.py
"""

import json
import os
import urllib.request

BASE = os.environ.get("DEMO_URL", "http://127.0.0.1:5000")
COLLECTOR = os.environ.get("COLLECTOR_URL", "http://127.0.0.1:5001")


def _get(url: str):
    with urllib.request.urlopen(url, timeout=5) as r:
        return json.loads(r.read())


def main():
    try:
        status = _get(f"{BASE}/status")
        cap = _get(f"{COLLECTOR}/captured")
        csp = _get(f"{BASE}/csp-report/log")
        rtm = _get(f"{BASE}/api/script-violation/log")
    except OSError as exc:
        print(f"Could not reach demo store or collector: {exc}")
        return 1

    print("=== Supply-chain scoreboard ===")
    print(f"  config         CSP_MODE={status['csp_mode']} SRI={status['sri']} "
          f"MONITOR={status['monitor']} VARIANT={status['skimmer_variant']}")
    print(f"  🔴 exfil        {cap['sensitive']} capture(s) with card/password "
          f"data   (total pings {cap['total']})")
    print(f"  🔵 CSP reports  {len(csp)} violation(s) logged")
    print(f"  🔵 runtime hits {len(rtm)} outbound call(s) flagged by the monitor")
    if rtm:
        for e in rtm[:3]:
            print(f"       {e['method']} → {e['url']}")
    verdict = "CONTAINED" if cap["sensitive"] == 0 else "SKIMMED"
    print(f"\n  verdict: {verdict}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
