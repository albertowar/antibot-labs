"""
Chapter 7: score a list of suspected takeovers against the answer key.

    python tools/score.py suspects.csv                     # tiers only, campaign names hidden
    python tools/score.py suspects.csv --prev suspects_r1.csv   # what this round added
    python tools/score.py suspects.csv --reveal            # names, misses and the red-herring story
    python tools/score.py suspects.csv --json out.json

suspects.csv needs an account_id column. Optional: score (higher = more suspicious;
without it the file order is the rank), first_event_id (graded as time-to-detect).

What it reports, in the series' shape: attacker success (victims found per
campaign and tier, and per compromise level), real users hurt (accounts flagged
per legitimate cohort against a 2% budget, worst first) and defender cost
(precision at the sizes of review queue an analyst can actually work).
"""

import argparse
import csv
import gzip
import hashlib
import json
import math
import os
import sys
from collections import OrderedDict

HERE = os.path.dirname(os.path.abspath(__file__))
LAB = os.path.dirname(HERE)
KEY = os.path.join(LAB, "solutions", "answer_key.json")
DATA = os.path.join(LAB, "data", "account_activity.jsonl.gz")
REVIEW_MIN = 5
BUDGET = 0.02
TIER_NAMES = {"A": "rules", "B": "graph", "C": "model"}


def budget_for(n):
    return max(1, math.floor(BUDGET * n))


def read_suspects(path):
    with open(path, newline="") as f:
        rows = list(csv.DictReader(f))
    if rows and "account_id" not in rows[0]:
        raise SystemExit(f"{path}: needs an account_id column (got {list(rows[0].keys())})")
    seen = OrderedDict()
    dups = 0
    for r in rows:
        a = (r.get("account_id") or "").strip()
        if not a:
            continue
        if a in seen:
            dups += 1
            continue
        s = r.get("score")
        try:
            s = float(s) if s not in (None, "") else None
        except ValueError:
            s = None
        seen[a] = {"score": s, "first_event_id": (r.get("first_event_id") or "").strip() or None}
    ranked = list(seen.keys())
    has_scores = all(v["score"] is not None for v in seen.values()) and len(seen) > 0
    if has_scores:
        ranked.sort(key=lambda a: -seen[a]["score"])
    return seen, ranked, has_scores, dups


def file_sha256(path):
    h = hashlib.sha256()
    opener = gzip.open if path.endswith(".gz") else open
    with opener(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def event_index(path, wanted):
    """Positions and timestamps of the event ids we need, from one pass over the log."""
    out = {}
    opener = gzip.open if path.endswith(".gz") else open
    with opener(path, "rt") as f:
        for n, line in enumerate(f):
            i = line.find('"event_id":"')
            if i < 0:
                continue
            eid = line[i + 12: i + 23]
            if eid in wanted:
                j = line.find('"ts":"')
                out.setdefault(eid, (n, line[j + 6: j + 30]))
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("suspects")
    ap.add_argument("--key", default=KEY)
    ap.add_argument("--data", default=DATA, help="the log, for the integrity check and time-to-detect")
    ap.add_argument("--prev", help="the previous round's suspects file")
    ap.add_argument("--reveal", action="store_true", help="show campaign names, misses and the red herrings' stories")
    ap.add_argument("--json", help="also write the report as JSON")
    ap.add_argument("--no-hash", action="store_true", help="skip the data integrity check")
    ap.add_argument("--k", default="25,50,100")
    args = ap.parse_args()

    with open(args.key) as f:
        key = json.load(f)
    suspects, ranked, has_scores, dups = read_suspects(args.suspects)
    prev = set(read_suspects(args.prev)[0].keys()) if args.prev else set()
    flagged = set(suspects)

    victims = {}
    for cname, c in key["campaigns"].items():
        for v in c["accounts"]:
            victims[v["account_id"]] = dict(v, campaign=cname, tier=c["tier"])
    cohorts = key["cohorts"]
    info = key["cohort_info"]
    all_accounts = set()
    for ids in cohorts.values():
        all_accounts.update(ids)
    all_accounts.update(victims)
    unknown = sorted(a for a in flagged if a not in all_accounts)

    report = {"file": args.suspects, "flagged": len(flagged), "ranked_by": "score" if has_scores else "file order", "warnings": []}
    if dups:
        report["warnings"].append(f"{dups} duplicate account ids ignored")
    if unknown:
        report["warnings"].append(f"{len(unknown)} account ids not in the dataset (e.g. {unknown[:3]})")
    if len(flagged) > 0.05 * len(all_accounts):
        report["warnings"].append(f"{len(flagged)} accounts flagged is more than 5% of the population; no analyst team reviews that")
    if not args.no_hash and os.path.exists(args.data):
        digest = file_sha256(args.data)
        if digest != key.get("sha256_uncompressed"):
            report["warnings"].append("data/account_activity.jsonl.gz does not match the answer key (regenerate with tools/make_log.py, default seed)")
    elif not args.no_hash:
        report["warnings"].append(f"{args.data} not found; skipped the integrity check")

    # --- attacker side: recall per campaign, tier, level
    camps = []
    tier_tot = {}
    level_tot = {}
    cidx = 0
    for cname, c in key["campaigns"].items():
        cidx += 1
        ids = [v["account_id"] for v in c["accounts"]]
        caught = [a for a in ids if a in flagged]
        new = [a for a in caught if a not in prev]
        camps.append({"campaign": cname, "label": cname if args.reveal else f"campaign {c['tier']}-{cidx}", "tier": c["tier"], "total": len(ids), "caught": len(caught), "new": len(new),
                      "missed": sorted(set(ids) - set(caught)) if args.reveal else None})
        t = tier_tot.setdefault(c["tier"], [0, 0])
        t[0] += len(caught)
        t[1] += len(ids)
        for v in c["accounts"]:
            lv = level_tot.setdefault(v["level"], [0, 0])
            lv[0] += v["account_id"] in flagged
            lv[1] += 1
    total_v = len(victims)
    tp = len(flagged & set(victims))
    fp = len(flagged) - tp - len(unknown)
    report["campaigns"] = camps
    report["tiers"] = {t: {"caught": v[0], "total": v[1]} for t, v in sorted(tier_tot.items())}
    report["levels"] = {t: {"caught": v[0], "total": v[1]} for t, v in sorted(level_tot.items())}
    report["recall"] = tp / total_v if total_v else 0
    report["precision"] = tp / len(flagged) if flagged else 0
    bonus_ids = {v["account_id"] for lst in key.get("bonus", {}).values() for v in lst}
    report["bonus_caught"] = len(flagged & bonus_ids)
    report["bonus_total"] = len(bonus_ids)

    # --- queue metrics
    ks = [int(x) for x in args.k.split(",")]
    queue = {}
    for k in ks:
        top = ranked[:k]
        hit = sum(1 for a in top if a in victims)
        queue[k] = {"precision": hit / len(top) if top else 0, "recall": hit / total_v if total_v else 0}
    report["queue"] = queue
    report["analyst_hours"] = len(flagged) * REVIEW_MIN / 60

    # --- real users hurt: per cohort against the budget (victims excluded from cohort counts)
    rows = []
    for name, ids in cohorts.items():
        legit = [a for a in ids if a not in victims]
        if not legit:
            continue
        hit = [a for a in legit if a in flagged]
        b = budget_for(len(legit))
        rows.append({"cohort": name, "flagged": len(hit), "size": len(legit), "rate": len(hit) / len(legit), "budget": b, "ok": len(hit) <= b,
                     "red_herring": info.get(name, {}).get("red_herring", False), "why": info.get(name, {}).get("why", "")})
    rows.sort(key=lambda r: (-r["rate"], -r["flagged"]))
    report["cohorts"] = rows
    over = [r for r in rows if not r["ok"]]

    # --- time to detect
    ttd = None
    pairs = [(a, s["first_event_id"]) for a, s in suspects.items() if s["first_event_id"] and a in victims]
    if pairs and os.path.exists(args.data):
        wanted = set(e for _, e in pairs) | set(victims[a]["first_compromise_event_id"] for a, _ in pairs)
        idx = event_index(args.data, wanted)
        within = 0
        for a, e in pairs:
            t = victims[a]["first_compromise_event_id"]
            if e in idx and t in idx:
                if abs(idx[e][0] - idx[t][0]) <= 10 or abs(_ts(idx[e][1]) - _ts(idx[t][1])) <= 3600:
                    within += 1
        ttd = {"given": len(pairs), "within_1h_or_10_events": within}
    report["time_to_detect"] = ttd

    # --- print
    p = print
    p(f"=== {os.path.basename(args.suspects)}: {len(flagged)} accounts flagged (ranked by {report['ranked_by']}) ===")
    p("Attacker side: confirmed takeovers found" + ("" if args.reveal else "   (names hidden; --reveal after Round 3)"))
    for c in camps:
        newtxt = f"   +{c['new']} this round" if args.prev else ""
        p(f"  tier {c['tier']} ({TIER_NAMES[c['tier']]:5s})  {c['label']:<28s} {c['caught']:>2}/{c['total']:<2} ({c['caught'] / c['total']:4.0%}){newtxt}")
        if args.reveal and c["missed"]:
            p(f"        missed: {', '.join(c['missed'])}")
    p("  tiers: " + "   ".join(f"{t} {v['caught']}/{v['total']}" for t, v in report["tiers"].items()) + f"   overall recall {tp}/{total_v} ({report['recall']:.0%})")
    p("  by compromise level: " + "   ".join(f"{t} {v['caught']}/{v['total']}" for t, v in report["levels"].items()))
    if report["bonus_total"]:
        p(f"  bonus campaign D (unscored): {report['bonus_caught']}/{report['bonus_total']}")
    p(f"Defender cost: precision {tp}/{len(flagged)} ({report['precision']:.1%}); " + "  ".join(f"p@{k} {q['precision']:.0%} (recall {q['recall']:.0%})" for k, q in queue.items())
      + f"; {len(flagged)} reviews x {REVIEW_MIN} min = {report['analyst_hours']:.1f} analyst-hours")
    p(f"Real users hurt: {len(over)} cohort(s) over the {BUDGET:.0%} budget (budget = max(1, floor(2% of cohort)))")
    p(f"  {'cohort':<22s} {'flagged':>7s} {'size':>6s} {'rate':>6s}  {'budget':>6s}")
    for r in rows:
        if r["flagged"] == 0 and r["ok"]:
            continue
        mark = "ok  " if r["ok"] else "OVER"
        why = f"   {r['why']}" if (args.reveal or not r["ok"]) and r["red_herring"] else ""
        p(f"  {r['cohort']:<22s} {r['flagged']:>7d} {r['size']:>6d} {r['rate']:>6.1%}  {r['budget']:>4d} {mark}{why}")
    quiet = [r["cohort"] for r in rows if r["flagged"] == 0]
    if quiet:
        p(f"  untouched: {', '.join(quiet)}")
    if ttd:
        p(f"Time to detect: {ttd['within_1h_or_10_events']}/{ttd['given']} first_event_id values are within 1 h (or 10 events) of the true first compromise")
    for w in report["warnings"]:
        p(f"WARNING: {w}")
    if args.json:
        with open(args.json, "w") as f:
            json.dump(report, f, indent=1, default=str)
        p(f"wrote {args.json}")


def _ts(s):
    # "2026-10-01T07:36:09.764Z" -> seconds, enough for a 1 h comparison
    return int(s[8:10]) * 86400 + int(s[11:13]) * 3600 + int(s[14:16]) * 60 + int(s[17:19]) + (int(s[5:7]) * 31 * 86400)


if __name__ == "__main__":
    main()
