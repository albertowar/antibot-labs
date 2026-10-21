"""
Round 4 reference: reports, the partner bank's indicators and campaign clustering, added to Round 2.

The dispersed crew (tier D) has one or two targets per account and nothing odd about any single
account. It is visible only as a network: accounts that share operator phones, payout handles the
partner bank has seen in complaints, a link domain nobody honest uses, and victims who report.

Seeds (evidence of scam, never of mere association):
  * two or more distinct members reported it for a scam;
  * it shared, in a message, a payout handle or link domain on the partner bank's list;
  * "follow the money": two or more payers of a listed handle had it as the new contact they talk to
    most (ten or more messages) among those who asked them to move apps.
Edges (association only): shared device, shared non-community link domain, and members whose
victims (two or more each) paid the same recently created handle. A connected component is taken down only if it contains a seed, so a
household's shared tablet never flags anyone on its own. Intel is a lead, not a verdict: one
listed handle belongs to an honest seller with a disputed chargeback.

    python solutions/round4_network.py           # writes out/reference/suspects_r4.csv (Round 2 + Round 4)
"""
from collections import Counter, defaultdict

import _ref
import round2_shape
import trailmates as tm

NEW_HANDLE_DAYS = 120     # money edges only through recently created payout handles; a seller's
                          # years-old handle links every seller who ever promoted to the same buyers
BOND_MSGS = 10           # attribute a payment to a contact only after a real conversation; a promo
                          # or a festival hello that said "add me" is not who the payer is paying
MAX_COMPONENT = 60        # bigger than any crew: an association chain gone wrong, not a campaign


def detect(feats=None):
    feats = feats or tm.member_features()
    out = dict(round2_shape.detect(feats))
    mem = tm.members()
    genuine = set(tm.world()["genuine_domains"])
    listed = {i["value"] for i in tm.intel()}
    seeds = Counter()
    reporters = defaultdict(set)
    for r in tm.reports():
        if r["reason"] == "scam":
            reporters[r["reported"]].add(r["reporter"])
    for m, rs in reporters.items():
        if len(rs) >= 2:
            seeds[m] += len(rs)
    sharers = defaultdict(set)            # handle or domain -> members who sent it
    for e in tm.dm_events():
        for ref in (e["payout_ref"], e["link"]):
            if ref and ref not in genuine:
                sharers[ref].add(e["sender"])
    for ref in listed:
        for m in sharers.get(ref, ()):
            seeds[m] += 2
    contact_by_handle = defaultdict(Counter)   # new handle -> off-platform contacts of its payers
    for p in tm.payments():
        if p["payee_kind"] == "external" and p["offplatform_contact"] and p["payee_age_days"] <= NEW_HANDLE_DAYS \
                and p["offplatform_contact_msgs"] >= BOND_MSGS:
            contact_by_handle[p["payee"]][p["offplatform_contact"]] += 1
    for h in listed:
        for m, n in contact_by_handle.get(h, {}).items():
            if n >= 2:
                seeds[m] += 2
    # union-find over association edges
    parent = {m: m for m in mem}

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a, b):
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[max(ra, rb)] = min(ra, rb)
    by_device = defaultdict(list)
    for m, r in mem.items():
        by_device[r["device_id"]].append(m)
    groups = list(by_device.values()) + [list(s) for s in sharers.values()]
    for h, cnt in contact_by_handle.items():
        groups.append([m for m, n in cnt.items() if n >= 2])
    for g in groups:
        for x in g[1:]:
            union(g[0], x)
    comp = defaultdict(list)
    for m in mem:
        comp[find(m)].append(m)
    for root, ms in comp.items():
        ev = sum(seeds[m] for m in ms)
        if ev == 0 or len(ms) > MAX_COMPONENT:
            continue
        for m in ms:
            if m not in out:
                out[m] = 0.5 + min(ev, 20) / 10 + seeds[m] / 10
    return out


if __name__ == "__main__":
    p = tm.write_suspects(_ref.path("suspects_r4.csv"), detect())
    _ref.score([p, "--prev", _ref.path("suspects_r2.csv")] if __import__("os").path.exists(_ref.path("suspects_r2.csv")) else [p])
