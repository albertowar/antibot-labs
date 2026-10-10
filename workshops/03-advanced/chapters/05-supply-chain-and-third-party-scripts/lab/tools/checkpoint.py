"""
checkpoint.py — are you where this round should be?

Reads how the demo store is configured, re-runs the round's attack, and checks
BOTH sides: did the skimmer get card data out, and did any real shopper get
blocked. Round 1 is special — there the lesson is that detection alone does not
stop exfil, so it checks the change-monitor fired AND the card still got out.

Run (demo store + collector up):
    python tools/checkpoint.py --round 2
    python tools/checkpoint.py --round 1 --catch-up   # print the right commands
"""

import argparse
import json
import os
import subprocess
import sys
import urllib.request

HERE = os.path.dirname(__file__)
LAB = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(LAB, "attacks"))

BASE = os.environ.get("DEMO_URL", "http://127.0.0.1:5000")
COLLECTOR = os.environ.get("COLLECTOR_URL", "http://127.0.0.1:5001")
PY = sys.executable

# Per round: the server state the student should be running, and what "passing"
# means. exfil_blocked=False for Round 1 (detection only).
ROUNDS = {
    1: dict(env=dict(VENDOR="compromised", SKIMMER_VARIANT="beacon",
                     CSP_MODE="off", SRI="off", MONITOR="off"),
            exfil_blocked=False, want_change_alert=True, want_runtime_alert=False),
    2: dict(env=dict(VENDOR="compromised", SKIMMER_VARIANT="dynamic",
                     CSP_MODE="enforce", SRI="off", MONITOR="off"),
            exfil_blocked=True, want_change_alert=False, want_runtime_alert=False),
    3: dict(env=dict(VENDOR="compromised", SKIMMER_VARIANT="allowlisted",
                     CSP_MODE="strict", SRI="on", MONITOR="off"),
            exfil_blocked=True, want_change_alert=False, want_runtime_alert=False),
    4: dict(env=dict(VENDOR="compromised", SKIMMER_VARIANT="firstparty",
                     CSP_MODE="strict", SRI="on", MONITOR="on",
                     TRUSTED_ANALYTICS=COLLECTOR),
            exfil_blocked=True, want_change_alert=False, want_runtime_alert=True),
}

_STATUS_KEY = {"VENDOR": "vendor", "SKIMMER_VARIANT": "skimmer_variant",
               "CSP_MODE": "csp_mode", "SRI": "sri", "MONITOR": "monitor",
               "TRUSTED_ANALYTICS": "trusted_analytics"}
_BOOL = {"on": True, "off": False}


def launch_cmd(env: dict) -> str:
    kv = " ".join(f"{k}={v}" for k, v in env.items())
    return f"{kv} python demo_site/app.py"


def status() -> dict:
    with urllib.request.urlopen(f"{BASE}/status", timeout=5) as r:
        return json.loads(r.read())


def state_matches(env: dict, st: dict) -> bool:
    for k, v in env.items():
        want = _BOOL[v] if k in ("SRI", "MONITOR") else v
        if st.get(_STATUS_KEY[k]) != want:
            return False
    return True


def change_alerts() -> int:
    """Crawl + diff. Returns the number of supply-chain alerts (>0 means caught)."""
    inv = os.path.join(LAB, "defenses", "inventory_scripts.py")
    mon = os.path.join(LAB, "defenses", "script_monitor.py")
    subprocess.run([PY, inv, "--base", BASE], cwd=LAB, check=False,
                   stdout=subprocess.DEVNULL)
    r = subprocess.run([PY, mon], cwd=LAB, check=False,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    # script_monitor exits 1 when it finds alerts (or has no baseline).
    return r.returncode


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("--round", type=int, required=True, choices=[1, 2, 3, 4])
    ap.add_argument("--catch-up", action="store_true",
                    help="print the exact commands to reach this round's state")
    args = ap.parse_args()
    cfg = ROUNDS[args.round]

    if args.catch_up:
        print(f"Round {args.round}: start the store with\n")
        print("   cd demo_site && " + launch_cmd(cfg["env"]) + "\n")
        if args.round == 1:
            print("First build the known-good baseline, then stage the swap:\n")
            print("   # 1) clean release")
            print("   cd demo_site && VENDOR=clean python app.py   # in another shell")
            print("   python defenses/inventory_scripts.py")
            print("   python defenses/script_monitor.py --create-baseline")
            print("   # 2) restart the store with the default (compromised) vendor file")
        return 0

    try:
        st = status()
    except OSError:
        print(f"❌ Demo store not reachable on {BASE}. Is it running?")
        return 1

    print(f"=== Checkpoint: Round {args.round} ===")
    if not state_matches(cfg["env"], st):
        print("❌ Server is not in this round's state. Restart it with:\n")
        print("     cd demo_site && " + launch_cmd(cfg["env"]))
        return 1
    print(f"  server OK: CSP_MODE={st['csp_mode']} SRI={st['sri']} "
          f"MONITOR={st['monitor']} VARIANT={st['skimmer_variant']}\n")

    failures = 0

    # ── Bot side: run the round's attack ──
    import _common
    attack = __import__({1: "round1_vendor_skimmer", 2: "round2_checkout_only",
                         3: "round3_allowlist_bypass", 4: "round4_poisoned_bundle"}[args.round])
    cap = attack.run(BASE)
    got_out = cap["sensitive"] > 0
    if cfg["exfil_blocked"]:
        ok = not got_out
        print(f"  {'✅' if ok else '❌'} exfil blocked "
              f"({cap['sensitive']} sensitive capture(s) — want 0)")
    else:
        ok = got_out
        print(f"  {'✅' if ok else '❌'} exfil succeeds as expected "
              f"({cap['sensitive']} capture(s) — detection alone does not stop it)")
    failures += not ok

    # ── Detection signals ──
    if cfg["want_change_alert"]:
        rc = change_alerts()
        ok = rc != 0
        print(f"  {'✅' if ok else '❌'} change-monitor flagged the swapped vendor file"
              + ("" if ok else "  (did you build the baseline? see --catch-up)"))
        failures += not ok

    if cfg["want_runtime_alert"]:
        hits = json.loads(urllib.request.urlopen(f"{BASE}/api/script-violation/log",
                                                  timeout=5).read())
        ok = len(hits) > 0
        print(f"  {'✅' if ok else '❌'} runtime monitor flagged the first-party call-out "
              f"({len(hits)} report(s))")
        failures += not ok

    # ── Human side ──
    import legit_traffic
    shoppers = legit_traffic.run(BASE, count=5)
    broken = [s for s in shoppers if not s["ok"]]
    ok = not broken
    print(f"  {'✅' if ok else '❌'} real shoppers: {len(broken)}/{len(shoppers)} blocked")
    failures += not ok

    print()
    if failures:
        print(f"❌ {failures} check(s) differ from the expected results. "
              f"Re-read the round, or run with --catch-up.")
        return 1
    print(f"✅ Round {args.round} checkpoint passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
