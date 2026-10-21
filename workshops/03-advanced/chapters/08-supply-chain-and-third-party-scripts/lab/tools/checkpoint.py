"""
Round checkpoint for W3 Ch8 (Supply Chain & Third-Party Scripts). Declares the rounds and hands over to
checkpoint_core.

    python tools/checkpoint.py --round 3              # set level 3, run the round's skimmer and the 6 browser shoppers
    python tools/checkpoint.py --round 3 --level 2    # the same skimmer against Round 2's defense (the "before")
    python tools/checkpoint.py --round 3 --catch-up   # install solutions/round1..3 (ladder.py), your file kept as .bak
    python tools/checkpoint.py --restore              # put your own file back
    python tools/checkpoint.py --all --markdown       # every round (the README's expected-results table)

This lab is PRE-WRITTEN: every control ships complete and a round is a DEFENSE_LEVEL. The store (and the
attacker's collector, started for you if none is listening) must be running; a round runs a pair of victims
through a real browser as the skimmer's audience, next to six browser shoppers.

    round  level  adds                                      skimmer (victims skimmed, of 2: checkout card + login password)
    -----  -----  ----------------------------------------  --------------------------------------------------------------
      1    1      inventory + change detection              beacon: both (detection is not prevention)
      2    2      CSP allowlist (Report-Only, then enforce)  dynamic: both under Report-Only, none enforced
      3    3      CSP nonce + strict-dynamic, SRI           allowlisted: none
      4    4      runtime monitor                           first-party poisoned bundle: none

"Succeeded" is victims whose data reached the collector. Next to it run the shoppers (tools/personas_ch8.py):
none may be stopped, and none may see the store's OWN files refused by the policy. Defender cost is what the
policy does to people and to the on-call: shoppers hurt, first-party violations, the add-on report noise, the
SRI re-pin (tools/cdn_bump.py) and the gate time of the shoppers' requests.
"""

import atexit
import json
import os
import statistics
import subprocess
import sys
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import personas_ch8  # noqa: E402,F401  (registers the ch5_shop scenario)
import checkpoint_core  # noqa: E402
import cdn_bump  # noqa: E402
import slice_check  # noqa: E402
import labclient  # noqa: E402
from checkpoint_core import Round, main  # noqa: E402

LAB = os.path.abspath(os.path.join(HERE, ".."))
PY = sys.executable
GATE_MEDIAN_MAX_MS = 20.0
SHOPPERS = 6
_collector_proc = []


def ensure_collector():
    """The attacker's sink must be listening where the store points; start it (loopback only) if nothing is."""
    url = labclient.admin("GET", "/lab/supply/status")["collector"]
    try:
        urllib.request.urlopen(url + "/captured", timeout=2).read()
        return url
    except OSError:
        pass
    proc = subprocess.Popen([PY, os.path.join(LAB, "collector", "collector.py")], cwd=LAB,
                            env=dict(os.environ, COLLECTOR_URL=url), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    _collector_proc.append(proc)
    atexit.register(proc.terminate)
    for _ in range(50):
        try:
            urllib.request.urlopen(url + "/captured", timeout=1).read()
            print(f"[checkpoint] started the collector on {url}")
            return url
        except OSError:
            time.sleep(0.2)
    raise SystemExit(f"Could not start the collector on {url}. Run: python collector/collector.py")


def victims_ok(board, results, attacks):
    """Every victim finished the page (an erroring victim says nothing about the defense)."""
    bad = {n: a.get("victim_errors") for n, a in attacks.items() if a.get("victim_errors")}
    return (not bad, f"victims did not finish: {bad}")


def wire(level):
    return lambda board, results, attacks: slice_check.wire(level)


def shoppers(board, results, attacks):
    """First-party violations must be 0; report the add-on noise and the vendor refusals as costs."""
    fp = sum(r.get("csp_first_party", 0) for r in results)
    noise = sum(r.get("csp_addon", 0) for r in results)
    vendor = sum(r.get("csp_vendor", 0) for r in results)
    skim = sum(r.get("csp_skimmer", 0) for r in results)
    print(f"\nthe shoppers: {len(results)} browsers · first-party files refused by the policy: {fp}"
          f" · add-on pixel/script refused (report noise): {noise} · vendor file refused by SRI: {vendor}"
          f" · skimmer calls refused: {skim}")
    stuck = [f"{r['actor']}@{r.get('stage')}" for r in results if r.get("outcome") != "bought"]
    if stuck:
        print("  did not finish:", ", ".join(stuck))
    return (fp == 0, f"{fp} first-party resource(s) were refused for shoppers")


def gate_cost(board, results, attacks):
    rows = labclient.admin("GET", "/lab/decisions", params={"limit": 5000, "actor": "human:"})["items"]
    ms = [d["ms"] for d in rows]
    if not ms:
        return (False, "no shopper requests in the decision log")
    median = statistics.median(ms)
    print(f"defender cost: gate time of the shoppers' {len(ms)} requests: median {median:.2f} ms "
          f"(the controls ride the response, not the gate)")
    return (median < GATE_MEDIAN_MAX_MS, f"gate median {median:.2f} ms > {GATE_MEDIAN_MAX_MS} ms")


def change_detection(board, results, attacks):
    """Round 1: baseline the clean release, let the vendor swap the file, crawl again, expect CHANGED."""
    admin = labclient.admin
    run = lambda *a: subprocess.run([PY, *a], cwd=LAB, capture_output=True, text=True,
                                    env=dict(os.environ, DEMO_URL=labclient.BASE_URL))
    admin("POST", "/lab/supply/scenario", json={"vendor": "clean", "variant": "beacon"})
    run("defenses/inventory_scripts.py")
    run("defenses/script_monitor.py", "--create-baseline")
    clean = run("defenses/script_monitor.py")
    admin("POST", "/lab/supply/scenario", json={"vendor": "compromised"})
    run("defenses/inventory_scripts.py")
    swapped = run("defenses/script_monitor.py")
    lines = [l.strip() for l in swapped.stdout.splitlines() if l.strip().startswith(("CHANGED", "NEW", "REMOVED"))]
    print("\nchange detection (inventory crawl + hash diff against the clean release)")
    print(f"  clean release : {'no alerts' if clean.returncode == 0 else 'ALERT (unexpected)'}")
    for l in lines:
        print(f"  after the swap: {l}")
    ok = clean.returncode == 0 and any("analytics-helper.js" in l and l.startswith("CHANGED") for l in lines)
    return (ok, "the change monitor did not flag the swapped vendor file (and only that)")


def csp_evidence(directive_words):
    def check(board, results, attacks):
        ro, en = attacks.get("report_only", {}), attacks.get("enforce", {})
        reports = [r for r in labclient.admin("GET", "/lab/supply/csp-reports")
                   if r.get("blocked_uri") and "127.0.0.1" in str(r["blocked_uri"])]
        print(f"\nCSP reports: Report-Only run filed {ro.get('csp_reports')}, enforce run filed {len(reports)} naming the collector "
              f"({', '.join(sorted({str(r['directive']).split(' ')[0] for r in reports})) or 'none'})")
        bad = []
        if not ro.get("csp_reports"):
            bad.append("Report-Only filed no reports (nothing to learn from)")
        if not reports:
            bad.append("enforcement filed no report naming the collector")
        return (not bad, "; ".join(bad))
    return check


def sri_cost(board, results, attacks):
    res = cdn_bump.probe()
    print(f"\nthe SRI re-pin cost: vendor script ran when it serves the pinned release: {res['clean']} · a legitimate "
          f"new release: {res['updated']} (refused for every visitor until re-pinned) · the swapped file: {res['compromised']}")
    ok = res["clean"] and not res["updated"] and not res["compromised"]
    return (ok, f"SRI should run the pinned release and refuse both others, got {res}")


def monitor_evidence(board, results, attacks):
    a = attacks.get("poisoned", {})
    reports = labclient.admin("GET", "/lab/supply/violations")
    print(f"\nruntime monitor: {len(reports)} report(s)" + (f", first: {reports[-1]['method']} -> {reports[-1]['url']}" if reports else ""))
    return (a.get("monitor_reports", 0) >= 1 and bool(reports), "the runtime monitor reported nothing")


def make_round(level, description, attacks, expect, checks, **kw):
    return Round(level=level, description=description, scenario="ch5_shop", population_n=SHOPPERS, attacks=attacks, expect=expect,
                 solutions=("defenses/ladder.py",), extra_checks=[victims_ok, wire(level), *checks, shoppers, gate_cost], **kw)


ROUNDS = {
    1: make_round(1, "inventory and change detection: the swap is flagged, the card still leaves",
                  {"vendor_skimmer": "attacks/round1_vendor_skimmer.py"}, {"vendor_skimmer": "full"}, [change_detection]),
    2: make_round(2, "CSP: Report-Only teaches, enforcement stops the beacon",
                  {"report_only": "attacks/round2_checkout_only.py --report-only", "enforce": "attacks/round2_checkout_only.py"},
                  {"report_only": "full", "enforce": "blocked"}, [csp_evidence(("connect-src",))]),
    3: make_round(3, "nonce + strict-dynamic and SRI: no allowlist to bypass",
                  {"allowlist_bypass": "attacks/round3_allowlist_bypass.py"}, {"allowlist_bypass": "blocked"}, [sri_cost]),
    4: make_round(4, "runtime monitor: the poisoned first-party bundle is seen and its beacon refused",
                  {"poisoned": "attacks/round4_poisoned_bundle.py"}, {"poisoned": "blocked"}, [monitor_evidence]),
}

_check_round = checkpoint_core.check_round


def check_round(*args, **kwargs):
    """Make sure the attacker's collector is listening, then run the round."""
    labclient.wait_for_store()
    ensure_collector()
    return _check_round(*args, **kwargs)


checkpoint_core.check_round = check_round

if __name__ == "__main__":
    main(ROUNDS)
