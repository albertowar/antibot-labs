#!/usr/bin/env python3
"""
W4 Ch6 lab: score a round against the sealed answer key.

    python tools/score.py out/suspects_r1.csv                       # members you flagged (Rounds 1, 2, 4)
    python tools/score.py out/suspects_r2.csv --prev out/suspects_r1.csv   # what this round added
    python tools/score.py --actions out/actions_r3.csv              # payment interventions (Round 3)
    python tools/score.py out/suspects_r4.csv --reveal              # also print who you missed and why each cohort is a trap

A suspects file is CSV with an `account_id` column and an optional `score` (higher = more
suspicious; it sets the order for precision@k, otherwise file order does). An actions file is CSV
`payment_id,action` with action `warn` or `hold`; any payment not listed is allowed.

What it reports, and why:
  * recall per campaign and per tier: the tiers are built so each round's detector family catches
    one and misses the next; the per-tier line is how you see that.
  * false positives per cohort against a 2% budget (at least one person per cohort): a rule that
    is fine on average can still flag every newcomer, every seller or every guide.
  * precision@k: the review queue an analyst works top-down.
  * for Round 3, scam money prevented against genuine payments held and warned, per payer cohort
    (holds within 2%, warnings within 10%). These are simulated outcomes: each scam payment carries
    a sealed coin flip for "a warning would have stopped it" and "a hold would have", and stopping
    one payment stops the rest of that victim's chain. Measured in simulation, not in the field.
"""

import argparse
import csv
import gzip
import hashlib
import json
import math
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
LAB = os.path.dirname(HERE)
sys.path.insert(0, HERE)
import trailmates as tm  # noqa: E402

KEY = os.path.join(LAB, "solutions", "answer_key.json")
FP_RATE, WARN_RATE = 0.02, 0.10
REVIEW_MIN = 5


def budget_for(n, rate=FP_RATE):
    return max(1, math.floor(rate * n))


def load_key(path=KEY):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def data_digest():
    h = hashlib.sha256()
    for name in sorted(["members.jsonl", "dm_events.jsonl", "payments.jsonl", "reports.jsonl", "partner_intel.json"]):
        p = os.path.join(tm.DATA, name)
        if name == "dm_events.jsonl":
            with gzip.open(p + ".gz", "rb") as fh:
                blob = fh.read()
        else:
            with open(p, "rb") as fh:
                blob = fh.read()
        h.update(name.encode())
        h.update(blob)
    return h.hexdigest()


def read_order(path):
    with open(path, newline="", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    if rows and "account_id" not in rows[0]:
        raise SystemExit(f"{path}: needs an account_id column")
    if rows and rows[0].get("score") not in (None, ""):
        rows.sort(key=lambda r: -float(r["score"] or 0))
    seen, order = set(), []
    for r in rows:
        if r["account_id"] not in seen:
            seen.add(r["account_id"])
            order.append(r["account_id"])
    return order


def score_members(path, key, prev=None, ks=(10, 25, 50)):
    order = read_order(path)
    flagged = set(order)
    camp_of = {m: cid for cid, c in key["campaigns"].items() for m in c["members"]}
    cohort_of = {m: k for k, ms in key["cohorts"].items() for m in ms}
    victims = {v for c in key["campaigns"].values() for v in c["victims"]}
    unknown = [m for m in flagged if m not in camp_of and m not in cohort_of]
    out = {"file": os.path.relpath(path, LAB), "flagged": len(flagged), "unknown_ids": len(unknown)}
    caught = flagged & set(camp_of)
    out["scam_caught"], out["scam_total"] = len(caught), len(camp_of)
    out["recall"] = round(len(caught) / len(camp_of), 3)
    out["precision"] = round(len(caught) / len(flagged), 3) if flagged else 0.0
    out["campaigns"] = {cid: {"tier": c["tier"], "caught": len(flagged & set(c["members"])), "total": len(c["members"])}
                        for cid, c in sorted(key["campaigns"].items())}
    tiers = {}
    for cid, c in out["campaigns"].items():
        t = tiers.setdefault(c["tier"], {"caught": 0, "total": 0})
        t["caught"] += c["caught"]
        t["total"] += c["total"]
    for t in tiers.values():
        t["recall"] = round(t["caught"] / t["total"], 3)
    out["tiers"] = dict(sorted(tiers.items()))
    cohorts = {}
    for k, ms in key["cohorts"].items():
        n_fp = len(flagged & set(ms))
        b = budget_for(len(ms))
        cohorts[k] = {"size": len(ms), "flagged": n_fp, "budget": b, "over": n_fp > b}
    out["cohorts"] = cohorts
    out["cohorts_over_budget"] = sorted(k for k, c in cohorts.items() if c["over"])
    out["victims_flagged"] = len(flagged & victims)
    out["precision_at"] = {str(k): round(sum(1 for m in order[:k] if m in camp_of) / k, 3) for k in ks if len(order) >= k}
    out["analyst_hours"] = round(len(flagged) * REVIEW_MIN / 60, 1)
    out["flagged_share"] = round(len(flagged) / (len(camp_of) + len(cohort_of)), 4)
    if prev:
        p = set(read_order(prev))
        added = flagged - p
        out["added"] = {"accounts": len(added), "scam": len(added & set(camp_of)),
                        "precision": round(len(added & set(camp_of)) / len(added), 3) if added else None}
        prev_over = {k for k, ms in key["cohorts"].items() if len(p & set(ms)) > budget_for(len(ms))}
        out["newly_over_budget"] = sorted(set(out["cohorts_over_budget"]) - prev_over)
    return out


def score_actions(path, key):
    acts = {}
    with open(path, newline="", encoding="utf-8") as fh:
        for r in csv.DictReader(fh):
            a = (r.get("action") or "allow").strip().lower()
            if a not in ("allow", "warn", "hold"):
                raise SystemExit(f"{path}: action must be allow, warn or hold (got {a!r})")
            if a != "allow":
                acts[r["payment_id"]] = a
    pays = {p["payment_id"]: p for p in tm.payments()}
    truth = key["scam_payments"]
    tier_of = {cid: c["tier"] for cid, c in key["campaigns"].items()}
    chains = {}
    for pid, t in truth.items():
        chains.setdefault(t["chain"], []).append((t["step"], pid))
    total = {"A": 0.0, "B": 0.0, "C": 0.0, "D": 0.0}
    saved = dict.fromkeys(total, 0.0)
    protected = stopped = 0
    for ch, steps in chains.items():
        steps.sort()
        tier = tier_of[truth[steps[0][1]]["campaign"]]
        amounts = [pays[pid]["amount"] for _, pid in steps]
        total[tier] += sum(amounts)
        for i, (_, pid) in enumerate(steps):
            a = acts.get(pid)
            if (a == "hold" and truth[pid]["hold_stop"]) or (a == "warn" and truth[pid]["warn_stop"]):
                saved[tier] += sum(amounts[i:])
                stopped += 1
                protected += i == 0
                break
    cohort_of = {m: k for k, ms in key["cohorts"].items() for m in ms}
    coh = {}
    for pid, p in pays.items():
        if pid in truth:
            continue
        k = cohort_of.get(p["payer"], "other")
        c = coh.setdefault(k, {"payments": 0, "warned": 0, "held": 0})
        c["payments"] += 1
        a = acts.get(pid)
        if a == "warn":
            c["warned"] += 1
        elif a == "hold":
            c["held"] += 1
    for c in coh.values():
        c["hold_budget"], c["warn_budget"] = budget_for(c["payments"]), budget_for(c["payments"], WARN_RATE)
        c["over"] = c["held"] > c["hold_budget"] or c["warned"] > c["warn_budget"]
    T, S = sum(total.values()), sum(saved.values())
    return {"file": os.path.relpath(path, LAB), "actions": len(acts),
            "scam_value": round(T, 2), "prevented_value": round(S, 2), "prevented_share": round(S / T, 3) if T else 0.0,
            "tiers": {t: {"value": round(total[t], 2), "prevented": round(saved[t], 2),
                          "share": round(saved[t] / total[t], 3) if total[t] else 0.0} for t in total},
            "chains": len(chains), "chains_stopped": stopped, "victims_fully_protected": protected,
            "scam_payments_held": sum(1 for pid in truth if acts.get(pid) == "hold"),
            "scam_payments_warned": sum(1 for pid in truth if acts.get(pid) == "warn"),
            "genuine": dict(sorted(coh.items())),
            "genuine_held": sum(c["held"] for c in coh.values()), "genuine_warned": sum(c["warned"] for c in coh.values()),
            "cohorts_over_budget": sorted(k for k, c in coh.items() if c["over"])}


def print_members(r, key, reveal=False):
    print(f"\n{r['file']}: {r['flagged']} flagged · {r['scam_caught']}/{r['scam_total']} scam accounts "
          f"(recall {r['recall']:.0%}, precision {r['precision']:.0%}) · {r['analyst_hours']} analyst-hours to review")
    print("\n  tier   caught  recall")
    for t, v in r["tiers"].items():
        print(f"  {t:<6}{v['caught']:>4}/{v['total']:<4}{v['recall']:>6.0%}")
    print("\n  campaign  tier  caught")
    for cid, v in r["campaigns"].items():
        print(f"  {cid:<10}{v['tier']:<6}{v['caught']}/{v['total']}")
    print("\n  cohort                  size  flagged  budget")
    for k, v in sorted(r["cohorts"].items(), key=lambda kv: (-kv[1]["flagged"] / kv[1]["budget"], kv[0])):
        mark = "  OVER" if v["over"] else ""
        print(f"  {k:<22}{v['size']:>6}{v['flagged']:>9}{v['budget']:>8}{mark}")
        if v["over"] or (reveal and v["flagged"]):
            print(f"      why: {key['cohort_info'][k]}")
    print(f"\n  victims flagged as scammers: {r['victims_flagged']} (counted in their cohorts above)")
    if r["precision_at"]:
        print("  precision@k: " + "  ".join(f"@{k} {v:.0%}" for k, v in r["precision_at"].items()))
    if "added" in r:
        a = r["added"]
        print(f"  this round added {a['accounts']} accounts, {a['scam']} of them scam"
              + (f" (precision {a['precision']:.0%})" if a["precision"] is not None else ""))
        if r["newly_over_budget"]:
            print(f"  newly over budget: {', '.join(r['newly_over_budget'])}")
    if r["unknown_ids"]:
        print(f"  WARNING: {r['unknown_ids']} ids are not members of this dataset")
    if r["flagged_share"] > 0.05:
        print(f"  WARNING: you flagged {r['flagged_share']:.1%} of the community; nobody can review that queue")


def print_actions(r):
    print(f"\n{r['file']}: {r['actions']} interventions · scam money prevented {r['prevented_share']:.0%} "
          f"({r['prevented_value']:,.0f} of {r['scam_value']:,.0f}, simulated)")
    print(f"  chains stopped {r['chains_stopped']}/{r['chains']} · victims stopped before their first payment "
          f"{r['victims_fully_protected']} · scam payments held {r['scam_payments_held']}, warned {r['scam_payments_warned']}")
    print("\n  tier   scam value   prevented")
    for t, v in r["tiers"].items():
        print(f"  {t:<6}{v['value']:>11,.0f}{v['share']:>11.0%}")
    print("\n  payer cohort (genuine)  payments  held/budget  warned/budget")
    for k, v in r["genuine"].items():
        mark = "  OVER" if v["over"] else ""
        print(f"  {k:<22}{v['payments']:>9}{v['held']:>7}/{v['hold_budget']:<5}{v['warned']:>8}/{v['warn_budget']:<5}{mark}")
    print(f"\n  genuine payments held {r['genuine_held']}, warned {r['genuine_warned']}")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("suspects", nargs="?")
    ap.add_argument("--actions")
    ap.add_argument("--prev")
    ap.add_argument("--key", default=KEY)
    ap.add_argument("--k", default="10,25,50")
    ap.add_argument("--reveal", action="store_true")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--no-hash", action="store_true", help="skip the dataset digest check")
    args = ap.parse_args()
    key = load_key(args.key)
    if not args.no_hash and data_digest() != key["sha256"]:
        print("WARNING: data/ does not match the answer key; re-run  python tools/make_trailmates.py", file=sys.stderr)
    if args.actions:
        r = score_actions(args.actions, key)
        print(json.dumps(r, indent=1)) if args.json else print_actions(r)
    elif args.suspects:
        r = score_members(args.suspects, key, args.prev, tuple(int(x) for x in args.k.split(",")))
        print(json.dumps(r, indent=1)) if args.json else print_members(r, key, args.reveal)
        if args.reveal and not args.json:
            flagged = set(read_order(args.suspects))
            for cid, c in sorted(key["campaigns"].items()):
                missed = [m for m in c["members"] if m not in flagged]
                if missed:
                    print(f"  missed in {cid} ({c['tier']}): {len(missed)}  e.g. {', '.join(missed[:3])}")
    else:
        ap.print_help()


if __name__ == "__main__":
    main()
