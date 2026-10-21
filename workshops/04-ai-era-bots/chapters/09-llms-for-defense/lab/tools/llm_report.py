"""
W4 Ch9 — Triage and enforcement reports: both sides of every round

A detection rate on its own is half a result. Depending on the flags this
prints:

  --triage     triage quality vs ground truth, LLM beside the heuristic:
               precision/recall on bots, false positives per human cohort,
               injection success (bot sessions labelled human), unsure rate,
               and defender cost (tokens, $, latency).
  --live       real users blocked per cohort and bots blocked, at the edge
               (from the decision log), for Round 3 enforcement.

Ground truth is the actor label. The edge strips it before any defense runs;
it survives only in the decision log, which this report (the judge, not a
defense) reads back — exactly what tools/scoreboard.py does. Production has
no such column; that is why the chapter's defenses never see it.
"""

import argparse
import json
import sys
from collections import defaultdict

from sqlalchemy import bindparam, text

import labclient  # noqa: F401  (guard; also puts the lab root on sys.path)
from defenses.heuristic import classify as heuristic_classify
from defenses.llm import usd
from defenses.rule_store import make_engine, verdicts_t
from defenses.sessionize import card_for_sid, flatten

# bot family (the actor's middle part) -> the payload it carries, for the injection metric
PAYLOAD = {"inj_ua": "single", "inj_referer": "single", "inj_both": "single",
           "stitched": "stitched", "rule_bait": "bait", "flood": "flood"}
CHECKOUT_PATHS = ("/checkout", "/api/checkout", "/api/buy")


def pct(n, d):
    return f"{n}/{d} ({n / d:.0%})" if d else "-"


def prf(tp, fp, fn):
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    return prec, rec


def load_truth(conn):
    """{sid: {actor, is_bot, cohort, payload}} from the decision log."""
    rows = conn.execute(text("SELECT DISTINCT sid, actor FROM decisions WHERE sid IS NOT NULL"))
    out = {}
    for sid, actor in rows:
        actor = actor or "you"
        parts = actor.split(":")
        cohort = parts[1] if len(parts) > 1 else actor
        out[sid] = {"actor": actor, "is_bot": actor.startswith("bot:"),
                    "cohort": cohort, "payload": PAYLOAD.get(cohort)}
    return out


def verdicts_for(conn, run_id, tag):
    rows = conn.execute(verdicts_t.select().where(
        verdicts_t.c.run_id == run_id, verdicts_t.c.tag == tag)).mappings().all()
    return {r["sid"]: r for r in rows}


def triage_report(conn, run_id, tag, truth, expect=None):
    """LLM verdicts vs truth, with the heuristic computed on the same sessions."""
    vmap = verdicts_for(conn, run_id, tag)
    if not vmap:
        print(f"no verdicts for run={run_id} tag={tag}. Run defenses.triage first.")
        return 1
    llm = {"tp": 0, "fp": 0, "fn": 0, "tn": 0}
    heur = {"tp": 0, "fp": 0, "fn": 0, "tn": 0}
    fp_cohort = defaultdict(lambda: [0, 0])          # human cohort -> [labelled bot, total]
    injected = [0, 0]                                 # [labelled human, total injected bots]
    heur_inj = [0, 0]
    unsure = 0
    toks = pt = ct = 0
    est = False
    lat = []
    for sid, v in vmap.items():
        t = truth.get(sid)
        if not t:
            continue
        is_bot = t["is_bot"]
        label = v["label"]
        toks += (v["prompt_tokens"] or 0) + (v["completion_tokens"] or 0)
        pt += v["prompt_tokens"] or 0
        ct += v["completion_tokens"] or 0
        est = est or bool(v["est"])
        if v["latency_ms"]:
            lat.append(v["latency_ms"])
        unsure += label == "unsure"
        # LLM confusion: unsure counts as "not caught" for recall, "not blocked" for FP
        if is_bot:
            llm["tp"] += label == "bot"
            llm["fn"] += label != "bot"
        else:
            llm["fp"] += label == "bot"
            llm["tn"] += label != "bot"
            fp_cohort[t["cohort"]][1] += 1
            fp_cohort[t["cohort"]][0] += label == "bot"
        card = card_for_sid(conn, sid)
        hlabel = heuristic_classify(flatten(card))[0] if card else "human"
        if is_bot:
            heur["tp"] += hlabel == "bot"
            heur["fn"] += hlabel != "bot"
        else:
            heur["fp"] += hlabel == "bot"
            heur["tn"] += hlabel != "bot"
        if t.get("payload") in ("single", "stitched"):
            injected[1] += 1
            injected[0] += label == "human"
            heur_inj[1] += 1
            heur_inj[0] += hlabel == "human"

    lp, lr = prf(llm["tp"], llm["fp"], llm["fn"])
    hp, hr = prf(heur["tp"], heur["fp"], heur["fn"])
    n = len(vmap)
    lat_p50 = sorted(lat)[len(lat) // 2] if lat else 0.0
    tilde = "~" if est else ""

    print(f"Triage quality  run={run_id} tag={tag}  ({n} sessions judged)\n")
    print(f"  {'classifier':<24}{'precision':>10}{'recall':>9}{'unsure':>8}"
          f"{'tok/sess':>10}{'p50 ms':>9}{'$/1k':>9}")
    print(f"  {'heuristic':<24}{hp:>10.2f}{hr:>9.2f}{'-':>8}{'0':>10}{'0.0':>9}{'0':>9}")
    sess_tok = toks / n if n else 0
    print(f"  {'LLM (' + tag + ')':<24}{lp:>10.2f}{lr:>9.2f}{unsure / n:>8.0%}"
          f"{tilde + str(round(sess_tok)):>10}{lat_p50:>9.0f}{'$' + format(usd(pt, ct) / n * 1000, '.3f'):>9}")

    if injected[1]:
        print(f"\n  Injected bots labelled human:  LLM {pct(injected[0], injected[1])}   "
              f"heuristic {pct(heur_inj[0], heur_inj[1])}")
    tot = [0, 0]
    if fp_cohort:
        print("\n  False positives on real users (labelled bot), per cohort")
        for cohort, (b, t) in sorted(fp_cohort.items()):
            tot[0] += b
            tot[1] += t
            print(f"     {cohort:<20} {pct(b, t)}")
        print(f"     {'total':<20} {pct(tot[0], tot[1])}")

    failures = 0
    if expect:
        failures = _check(expect, {
            "precision": lp, "recall": lr,
            "inj_rate": injected[0] / injected[1] if injected[1] else 0.0,
            "human_fp": (tot[0] / tot[1]) if tot[1] else 0.0,
            "unsure_rate": unsure / n if n else 0.0,
            "tok_per_session": sess_tok})
    return failures


def _check(expect, got):
    failures = 0
    print("\n  Checks")
    for key, (lo, hi, label) in expect.items():
        val = got.get(key, 0.0)
        ok = lo <= val <= hi
        failures += not ok
        shown = f"{val:.0%}" if val <= 1.0 else f"{val:,.0f}"
        print(f"     {'OK ' if ok else 'FAIL'} {label:<40} {shown}")
    return failures


def live_report(conn, truth, expect=None):
    """Who got blocked at the edge: checkout decisions from the decision log."""
    q = text("SELECT sid, status FROM decisions WHERE path IN :paths AND method = 'POST'") \
        .bindparams(bindparam("paths", expanding=True))
    rows = conn.execute(q, {"paths": list(CHECKOUT_PATHS)}).all()
    status = {}
    for sid, st in rows:
        status[sid] = st                      # the last checkout decides
    bots = defaultdict(lambda: [0, 0])
    humans = defaultdict(lambda: [0, 0])
    for sid, t in truth.items():
        if sid not in status:
            continue
        blocked = status[sid] == 403
        bucket = bots if t["is_bot"] else humans
        bucket[t["cohort"]][0] += blocked
        bucket[t["cohort"]][1] += 1
    print("Live enforcement (checkout decisions)\n")
    print("  Bots blocked")
    btot = [0, 0]
    for k, (b, n) in sorted(bots.items()):
        btot[0] += b
        btot[1] += n
        print(f"     {k:<20} {pct(b, n)}")
    print(f"     {'total':<20} {pct(btot[0], btot[1])}")
    print("\n  Real users blocked (the cost)")
    htot = [0, 0]
    worst = 0.0
    for k, (b, n) in sorted(humans.items()):
        htot[0] += b
        htot[1] += n
        worst = max(worst, b / n if n else 0)
        print(f"     {k:<20} {pct(b, n)}")
    print(f"     {'total':<20} {pct(htot[0], htot[1])}")
    failures = 0
    if expect:
        failures = _check(expect, {"bots_blocked": btot[0] / btot[1] if btot[1] else 0.0,
                                   "humans_blocked": htot[0] / htot[1] if htot[1] else 0.0,
                                   "worst_cohort": worst})
    return failures


def main():
    ap = argparse.ArgumentParser(description="Score a round from both sides.")
    ap.add_argument("--triage", action="store_true")
    ap.add_argument("--live", action="store_true")
    ap.add_argument("--run", default="all")
    ap.add_argument("--tag", default="triage")
    ap.add_argument("--expect", default=None, help="JSON {key: [lo, hi, label]} to judge against")
    args = ap.parse_args()
    expect = json.loads(args.expect) if args.expect else None
    with make_engine().connect() as conn:
        truth = load_truth(conn)
        if args.live:
            return live_report(conn, truth, expect)
        return triage_report(conn, args.run, args.tag, truth, expect)


if __name__ == "__main__":
    sys.exit(main())
