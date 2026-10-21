#!/usr/bin/env python3
"""
W4 Ch6 lab tests: the generator is deterministic, and the tiers and traps the README table rests on hold.

    python tests/test_make_trailmates.py            # golden digest at scale 0.25 (a few seconds)
    python tests/test_make_trailmates.py --update   # rewrite tests/golden.json after a deliberate generator change
    python tests/test_make_trailmates.py --tiers    # also: each reference round catches its tier and misses the next,
                                                    # and every naive rule the notebooks start from trips its cohort

--tiers needs the full dataset in data/ (python tools/make_trailmates.py).
"""

import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
LAB = os.path.dirname(HERE)
sys.path[:0] = [os.path.join(LAB, "tools"), os.path.join(LAB, "solutions")]
import make_trailmates as mk  # noqa: E402
import score  # noqa: E402
import trailmates as tm  # noqa: E402

GOLDEN = os.path.join(HERE, "golden.json")
FAILS = []


def check(name, ok, detail=""):
    print(f"  [{'ok' if ok else 'FAIL'}] {name}" + (f"  ({detail})" if detail else ""))
    if not ok:
        FAILS.append(name)


def golden(update=False):
    with tempfile.TemporaryDirectory() as d:
        W = mk.generate(0.25)
        digest = mk.write_outputs(W, d, None)
    if update:
        with open(GOLDEN, "w", encoding="utf-8") as fh:
            json.dump({"scale": 0.25, "sha256": digest}, fh, indent=1)
            fh.write("\n")
        print(f"golden.json updated: {digest[:16]}…")
        return
    with open(GOLDEN, encoding="utf-8") as fh:
        want = json.load(fh)["sha256"]
    print("determinism")
    check("scale-0.25 dataset matches tests/golden.json", digest == want, f"{digest[:12]} vs {want[:12]}")


def suspects(scores):
    fd, p = tempfile.mkstemp(suffix=".csv")
    os.close(fd)
    tm.write_suspects(p, scores)
    return p


def actions(acts):
    fd, p = tempfile.mkstemp(suffix=".csv")
    os.close(fd)
    tm.write_actions(p, acts)
    return p


def over(r, cohort):
    return cohort in r["cohorts_over_budget"]


def tiers():
    import round1_profile
    import round2_shape
    import round3_interventions
    import round4_network
    key = score.load_key()
    check("data/ matches the answer key", score.data_digest() == key["sha256"])
    feats = tm.member_features()
    print("Round 1: account and profile rules")
    r1 = score.score_members(suspects(round1_profile.detect(feats)), key)
    t = r1["tiers"]
    check("reference catches tier A >= 90%", t["A"]["recall"] >= 0.9, f"{t['A']['recall']:.0%}")
    check("reference misses B, C and D (<= 10%)", all(t[x]["recall"] <= 0.1 for x in "BCD"))
    check("reference keeps every cohort within budget", not r1["cohorts_over_budget"], str(r1["cohorts_over_budget"]))
    naive = {m: 1 for m, f in feats.items() if f["age_at_first_outbound_days"] is not None
             and f["age_at_first_outbound_days"] <= 7 and f["fanout_48h"] >= 15}
    check("trap: new + burst fan-out alone puts newcomers over budget", over(score.score_members(suspects(naive), key), "newcomer"))
    naive = {m: 1 for m, f in feats.items() if f["photo_count_raw"] >= 3}
    check("trap: photo reuse counting default avatars puts default_avatar over budget",
          over(score.score_members(suspects(naive), key), "default_avatar"))
    naive = {m: 1 for m, f in feats.items() if f["egress"] in ("hosting", "vpn")}
    check("trap: hosting/VPN egress alone puts vpn_user over budget", over(score.score_members(suspects(naive), key), "vpn_user"))

    print("Round 2: conversation shape (cumulative)")
    r2 = score.score_members(suspects(round2_shape.detect(feats)), key)
    t = r2["tiers"]
    check("reference catches tier B >= 80%", t["B"]["recall"] >= 0.8, f"{t['B']['recall']:.0%}")
    check("reference misses C and D (<= 20%)", t["C"]["recall"] <= 0.2 and t["D"]["recall"] <= 0.2)
    check("reference keeps every cohort within budget", not r2["cohorts_over_budget"], str(r2["cohorts_over_budget"]))
    naive = {m: 1 for m, f in feats.items() if f["outbound_first"] >= 10 and f["early_offplatform_rate"] >= 0.15}
    check("trap: fan-out + early off-platform without the shift puts sellers over budget",
          over(score.score_members(suspects(naive), key), "seller"))
    naive = {m: 1 for m, f in feats.items() if f["outbound_first"] >= 10 and f["hour_concentration"] >= 0.95}
    check("trap: shift hours + fan-out without the off-platform move puts guides over budget",
          over(score.score_members(suspects(naive), key), "guide"))
    naive = {m: 1 for m, f in feats.items() if f["translated_share"] >= 0.5}
    check("trap: translation as a signal puts translation users over budget",
          over(score.score_members(suspects(naive), key), "translation_user"))

    print("Round 3: interventions")
    pays = tm.payments()
    r3 = score.score_actions(actions(round3_interventions.detect(pays)), key)
    check("reference prevents >= 70% of scam money", r3["prevented_share"] >= 0.7, f"{r3['prevented_share']:.0%}")
    check("reference keeps every payer cohort within budget", not r3["cohorts_over_budget"], str(r3["cohorts_over_budget"]))
    check("tier D is the weakest (the money moves where Round 3 cannot attribute it)",
          r3["tiers"]["D"]["share"] < min(r3["tiers"][x]["share"] for x in "BC"))
    check("the honest cost: new long-distance couples are held", r3["genuine"]["long_distance_couple"]["held"] >= 1)
    naive = {p["payment_id"]: "hold" for p in pays if p["first_to_payee"]}
    rn = score.score_actions(actions(naive), key)
    check("trap: holding every first payment puts regular members over the hold budget", "regular" in rn["cohorts_over_budget"])
    naive = {p["payment_id"]: "hold" for p in pays if p["first_to_payee"] and p["offplatform_contact"]}
    rn = score.score_actions(actions(naive), key)
    check("trap: any off-platform contact without the bond test goes over budget somewhere", bool(rn["cohorts_over_budget"]),
          str(rn["cohorts_over_budget"]))

    print("Round 4: reports, partner intel, clustering (cumulative)")
    r4 = score.score_members(suspects(round4_network.detect(feats)), key)
    t = r4["tiers"]
    check("reference catches tier D >= 80%", t["D"]["recall"] >= 0.8, f"{t['D']['recall']:.0%}")
    check("reference overall recall >= 90%", r4["recall"] >= 0.9, f"{r4['recall']:.0%}")
    check("reference keeps every cohort within budget", not r4["cohorts_over_budget"], str(r4["cohorts_over_budget"]))
    check("intel is a lead, not a verdict: the honest seller with a chargeback is flagged",
          r4["cohorts"]["seller"]["flagged"] >= 1)
    mem = tm.members()
    by_dev = {}
    for m, rec in mem.items():
        by_dev.setdefault(rec["device_id"], []).append(m)
    naive = {m: 1 for ms in by_dev.values() if len(ms) >= 2 for m in ms}
    check("trap: shared device alone, without a seed, puts households over budget",
          over(score.score_members(suspects(naive), key), "household"))


def main():
    update = "--update" in sys.argv
    golden(update)
    if update:
        return 0
    if "--tiers" in sys.argv:
        tiers()
    print(f"\n{'FAILED: ' + ', '.join(FAILS) if FAILS else 'all checks passed'}")
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
