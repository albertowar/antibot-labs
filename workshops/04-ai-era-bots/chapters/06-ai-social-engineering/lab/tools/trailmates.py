"""
W4 Ch6 lab helpers: load the Trailmates log and compute the per-member features the rounds use.

    import trailmates as tm
    members = tm.members()                 # member_id -> record
    feats = tm.member_features()           # member_id -> dict of account and conversation-shape features
    pays = tm.payments()                   # list of payment rows with their decision-time features
    tm.write_suspects("out/suspects_r1.csv", {"m_...": 1.0, ...})

Standard library only, so the scorer and the reference detectors run without the notebook stack.
`frames()` returns pandas DataFrames for the notebooks.

Every feature here is something a community's trust-and-safety team can compute from its own
records: when an account joined and from which network, which photo it uses, whom it messaged
first and at what hours, whether it asked someone to move to another app, what it was paid. None
of them reads message text. That is a design choice the chapter argues for: the metadata is where
the scam operation's costs show, and reading members' private messages is a decision with its own
legal and trust price (§6.5).
"""

import csv
import gzip
import json
import os
from collections import Counter, defaultdict
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
LAB = os.path.dirname(HERE)
DATA = os.path.join(LAB, "data")
OUT = os.path.join(LAB, "out")
DAY = 86400


def ts(s):
    return int(datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp())


def _need(path):
    if not os.path.exists(path):
        raise SystemExit(f"{os.path.relpath(path, LAB)} is missing: run  python tools/make_trailmates.py  first")
    return path


def world():
    with open(_need(os.path.join(DATA, "world.json")), encoding="utf-8") as fh:
        return json.load(fh)


def members():
    with open(_need(os.path.join(DATA, "members.jsonl")), encoding="utf-8") as fh:
        return {r["member_id"]: r for r in map(json.loads, fh)}


def dm_events():
    with gzip.open(_need(os.path.join(DATA, "dm_events.jsonl.gz")), "rt", encoding="utf-8") as fh:
        for line in fh:
            yield json.loads(line)


def payments():
    with open(_need(os.path.join(DATA, "payments.jsonl")), encoding="utf-8") as fh:
        return [json.loads(x) for x in fh]


def reports():
    with open(_need(os.path.join(DATA, "reports.jsonl")), encoding="utf-8") as fh:
        return [json.loads(x) for x in fh]


def intel():
    with open(_need(os.path.join(DATA, "partner_intel.json")), encoding="utf-8") as fh:
        return json.load(fh)


def asn_kind():
    return {a["asn"]: a["kind"] for a in world()["asns"]}


def best_window_share(hours, width=10):
    """Share of messages in the busiest `width` contiguous UTC hours (wrapping midnight)."""
    total = sum(hours)
    if not total:
        return 0.0
    best = max(sum(hours[(h + k) % 24] for k in range(width)) for h in range(24))
    return best / total


def member_features():
    """One pass over the message log. Returns member_id -> features (see the keys below)."""
    mem = members()
    kinds = asn_kind()
    defaults = set(world()["default_avatars"])
    photo_count = Counter(m["photo"] for m in mem.values())
    device_count = Counter(m["device_id"] for m in mem.values())
    f = {mid: {"joined": ts(m["joined_at"]), "egress": kinds[m["signup_asn"]],
               "default_avatar": m["photo"] in defaults,
               "photo_reuse": 0 if m["photo"] in defaults else photo_count[m["photo"]],
               "photo_count_raw": photo_count[m["photo"]],
               "shared_device": device_count[m["device_id"]],
               "region_mismatch": any(r != m["declared_region"] for r in m["login_regions"]),
               "sent": 0, "outbound_first": 0, "inbound_first": 0, "hours": [0] * 24, "weekend": 0,
               "translated": 0, "offplatform_sent": 0, "first_contact_times": [], "first_outbound": None}
         for mid, m in mem.items()}
    thread_first = {}          # thread -> (ts, initiator)
    early_off = defaultdict(set)
    for e in dm_events():
        t = ts(e["ts"])
        s = f[e["sender"]]
        s["sent"] += 1
        dt = datetime.fromtimestamp(t, timezone.utc)
        s["hours"][dt.hour] += 1
        s["weekend"] += dt.weekday() >= 5
        s["translated"] += e["translated"]
        if e["first_contact"]:
            thread_first[e["thread"]] = (t, e["sender"])
            s["outbound_first"] += 1
            s["first_contact_times"].append(t)
            if s["first_outbound"] is None:
                s["first_outbound"] = t
            f[e["recipient"]]["inbound_first"] += 1
        if e["offplatform"]:
            s["offplatform_sent"] += 1
            tf = thread_first.get(e["thread"])
            if tf and tf[1] == e["sender"] and t - tf[0] <= 7 * DAY:
                early_off[e["sender"]].add(e["thread"])
    for mid, s in f.items():
        times = sorted(s.pop("first_contact_times"))
        j = best = 0
        for i, t in enumerate(times):
            while t - times[j] > 2 * DAY:
                j += 1
            best = max(best, i - j + 1)
        s["fanout_48h"] = best
        s["age_at_first_outbound_days"] = None if s["first_outbound"] is None else \
            round((s["first_outbound"] - s["joined"]) / DAY, 2)
        s["early_offplatform_rate"] = round(len(early_off[mid]) / s["outbound_first"], 3) if s["outbound_first"] else 0.0
        s["hour_concentration"] = round(best_window_share(s["hours"]), 3)
        s["weekend_share"] = round(s["weekend"] / s["sent"], 3) if s["sent"] else 0.0
        s["translated_share"] = round(s["translated"] / s["sent"], 3) if s["sent"] else 0.0
        del s["hours"], s["weekend"], s["translated"], s["first_outbound"]
    return f


def write_suspects(path, scores):
    """scores: member_id -> score (higher = more suspicious). Writes account_id,score sorted by score."""
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["account_id", "score"])
        for mid, sc in sorted(scores.items(), key=lambda kv: (-kv[1], kv[0])):
            w.writerow([mid, round(sc, 4)])
    return path


def read_suspects(path):
    with open(path, newline="", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    return {r["account_id"]: float(r.get("score") or 0) for r in rows}


def write_actions(path, actions):
    """actions: payment_id -> 'warn' | 'hold' (anything missing is 'allow')."""
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["payment_id", "action"])
        for pid in sorted(actions):
            w.writerow([pid, actions[pid]])
    return path


def frames():
    """pandas DataFrames for the notebooks: members, dms, payments, reports, features."""
    import pandas as pd
    mem = pd.DataFrame(members().values())
    dms = pd.read_json(os.path.join(DATA, "dm_events.jsonl.gz"), lines=True, compression="gzip")
    dms["ts"] = pd.to_datetime(dms["ts"], utc=True)
    pays = pd.DataFrame(payments())
    pays["ts"] = pd.to_datetime(pays["ts"], utc=True)
    reps = pd.DataFrame(reports())
    feats = pd.DataFrame.from_dict(member_features(), orient="index")
    feats.index.name = "member_id"
    return {"members": mem, "dms": dms, "payments": pays, "reports": reps, "features": feats}
