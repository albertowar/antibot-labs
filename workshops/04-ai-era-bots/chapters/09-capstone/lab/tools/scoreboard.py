"""
W4 Ch9 Capstone — the governance scoreboard: three columns, both sides

Reads /admin/decisions and prints what W4 Ch8 asked the Capstone rubric to
measure. Three columns, split crawlers / shoppers:

  1. bots through        per campaign: content served free, drop orders placed,
                         injections landed. A CHARGED crawl is revenue, not a leak.
  2. legit blocked       per cohort: blocks + mazes + a challenge the cohort cannot
                         pass (an image CAPTCHA to a screen-reader user is a block).
  3. legit challenged    per cohort, WEIGHTED: each challenged legit session counts
     (weighted)          w_kind x seen.  w_kind: pow 0.2, confirm_code 1.0,
                         captcha_image 1.0.  seen = 1 only when a person answers it
                         (derived from the kind and the cohort, never from the client).

The cohort/campaign label is the lab-only X-Lab-Actor; no defense reads it.
Also prints scoring latency, the pay-per-crawl ledger, and the W2 shadow score.

    python tools/scoreboard.py
"""

import argparse
import os
import statistics
import sys
from collections import defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
LAB_DIR = os.path.dirname(HERE)
sys.path.insert(0, HERE)
from lab import BASE_URL, admin, ensure_local, server_status  # noqa: E402

W_KIND = {"pow": 0.2, "confirm_code": 1.0, "captcha_image": 1.0, None: 0.0}
# Which cohorts have a person in the loop to answer a code, and which cannot see an image.
HUMAN_IN_LOOP = {"shopper", "shared_ip", "vpn", "privacy", "a11y", "agent_shopper", "cloud_signed", "a11y_agent"}
CANNOT_SEE = {"a11y", "a11y_agent"}
SHOPPER_COHORTS = ["shopper", "shared_ip", "vpn", "privacy", "a11y", "agent_shopper", "cloud_signed", "a11y_agent"]


def _is_bot(actor):
    return actor.startswith("bot") or actor in ("local_agent_farm", "declared_then_undeclared", "forged_signature",
                                                "a11y_mimic", "score_probe")


def run(base=BASE_URL):
    ensure_local(base)
    rows = admin("GET", "/admin/decisions", params={"limit": 20000})
    status = server_status()
    print(f"=== Governance scoreboard (DEFENSE_LEVEL={status['level']}, policy {status.get('policy')}) ===\n")

    # 1. bots through
    print("1. Bots through")
    campaigns = defaultdict(lambda: defaultdict(int))
    for d in rows:
        a = d.get("actor", "")
        if not _is_bot(a):
            continue
        c = campaigns[a]
        c["decisions"] += 1
        if d["action"] == "checkout" and d["outcome"] == "allow":
            c["orders"] += 1
        if d["action"] == "content" and d["outcome"] in ("allow", "charged"):
            c["pages"] += 1
        if d["action"] == "content" and d["outcome"] == "charged":
            c["charged"] += 1
    if campaigns:
        for name in sorted(campaigns):
            c = campaigns[name]
            print(f"   {name:<26} orders {c['orders']:>3}  content served {c['pages']:>4}  charged {c['charged']:>3}")
    else:
        print("   (no bot traffic in the log)")

    # 2 & 3. legit, per cohort
    print("\n2/3. Legitimate users  (blocked = failure; challenged = weighted friction)")
    print(f"   {'cohort':<14}{'n':>4}{'allow':>7}{'block':>7}{'maze':>6}{'chal':>6}{'weighted':>10}")
    per = defaultdict(lambda: defaultdict(int))
    weighted = defaultdict(float)
    for d in rows:
        a = d.get("actor", "")
        if _is_bot(a) or a in ("unknown", "agent-owner", "audit"):
            continue
        cohort = a
        per[cohort]["n"] += 1
        out = d["outcome"]
        if d["action"] in ("checkout", "content"):
            if out in ("allow", "charged"):
                per[cohort]["allow"] += 1
            elif out == "block":
                per[cohort]["block"] += 1
            elif out == "maze":
                per[cohort]["maze"] += 1
            elif out == "challenge":
                kind = d.get("challenge_kind")
                if kind == "captcha_image" and cohort in CANNOT_SEE:
                    per[cohort]["block"] += 1          # a wall they cannot pass is a block
                else:
                    per[cohort]["chal"] += 1
                    seen = 1 if (cohort in HUMAN_IN_LOOP and kind in ("confirm_code", "captcha_image")) else 0
                    weighted[cohort] += W_KIND.get(kind, 0.0) * (seen if kind != "pow" else 1)
    total_block = 0
    for cohort in SHOPPER_COHORTS:
        c = per.get(cohort)
        if not c:
            continue
        total_block += c["block"] + c["maze"]
        flag = "  <-- FP" if (c["block"] + c["maze"]) else ""
        print(f"   {cohort:<14}{c['n']:>4}{c['allow']:>7}{c['block']:>7}{c['maze']:>6}{c['chal']:>6}{weighted[cohort]:>10.1f}{flag}")
    print(f"\n   legitimate users blocked or mazed: {total_block}  (target 0)")

    # defender cost + ledger
    timings = [d["score_ms"] for d in rows if d.get("score_ms") is not None and d["action"] == "checkout"]
    if timings:
        print(f"\nDefender cost: checkout scoring median {statistics.median(timings):.1f} ms "
              f"(n={len(timings)})")
    print(f"Pay-per-crawl ledger: {status.get('ledger', {})}")
    return {"campaigns": dict(campaigns), "legit_blocked": total_block}


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default=BASE_URL)
    run(ap.parse_args().url)
