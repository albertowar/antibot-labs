"""
Round 2 reference: shared infrastructure, found with a graph.

Rules see one account at a time. The phishing kit, the cookie buyer, the OAuth
hijacker and the support ring each touch many accounts with the *same* things:
a browser profile (device_id), a canvas fingerprint (fp_hash), a provider
identity (provider_sub_hash). The log is a bipartite graph of accounts and
identifiers; the attacker is a component in it.

Two moves, in order:

  1. Seed expansion. Round 1 gave us confirmed takeovers. Every identifier that
     appeared on those accounts for the first time at or after the compromise is
     attacker infrastructure. Any other account that shares one is a suspect.
     (The impossible-travel operator shares a fingerprint with the phishing kit.)
     Two guards, learned the hard way: only identifiers from events the *user*
     performed count (the store's own policy engine and the MFA-migration batch
     also touched the victims after the compromise, from service devices that
     touch hundreds of accounts), and an identifier seen on more than a dozen
     accounts is infrastructure of some kind, not evidence.

  2. Young, thin components. Build the account <-> identifier graph on device_id,
     fp_hash and provider_sub_hash. Keep an identifier only if it links 2 to 12
     accounts, every one of its edges was first seen on or after day 25, and the
     edges are thin (a handful of events each). Households share a desktop for
     months with hundreds of events; a couple shares a device from day one; a
     duplicate-account owner signs in with the same provider identity all quarter.
     The attacker touched each victim once or twice, recently. Project the
     survivors onto accounts and take every component. One more guard: if two
     accounts joined by a young, thin identifier *also* share an old, thick one
     (a desktop they have both used since the log began), they are one person
     with two accounts, not a victim and an attacker.

What the naive version does instead, and why it fails: linking on JA4 floods
(the kit's TLS stack is a real minority browser, shared by ~150 real people);
linking on IP floods on CGNAT and VPN; any degree threshold either misses the kit
(it rotates its cookie every few victims, so no device exceeds household degree)
or flags every household. The fake-account farm *is* a young, thin cluster, and
it is not a takeover: there was no owner before the farm. We report it separately
and keep it out of the suspects: look at an account's history before the shared
identifier appeared.

Run:
    python solutions/round2_graph.py            # needs solutions/checkpoints/suspects_r1.csv (run round1 first)
    python solutions/round2_graph.py --prev my_r1.csv --out my_r2.csv
"""

import argparse
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
LAB = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(LAB, "tools"))

import networkx as nx  # noqa: E402
import pandas as pd  # noqa: E402
from atolab import build_bipartite, component_report, dedupe, first_seen, load_events, project_accounts, save_suspects, score_now  # noqa: E402

KEYS = ("device_id", "fp_hash", "d_provider_sub_hash")
MAX_SPREAD = 12
DAY25 = pd.Timestamp("2026-10-26", tz="UTC")


def seed_expansion(df, seeds):
    """Identifiers that first appeared on a seed account at/after its flagged event -> other accounts sharing them."""
    seeds = seeds.dropna(subset=["first_event_id"])
    ev = df[["event_id", "ts"]].set_index("event_id")["ts"]
    seeds = seeds.assign(t0=seeds["first_event_id"].map(ev)).dropna(subset=["t0"])
    bad = set()
    user_rows = df[df["actor"] == "user"]
    spread = {key: user_rows.groupby(key, observed=True)["account_id"].nunique() for key in ("device_id", "fp_hash")}
    for key in ("device_id", "fp_hash"):
        for r in seeds.itertuples(index=False):
            a = user_rows[(user_rows["account_id"] == r.account_id)]
            before = set(a.loc[a["ts"] < r.t0, key].dropna().astype(str))
            after = set(a.loc[a["ts"] >= r.t0, key].dropna().astype(str))
            bad |= {(key, v) for v in after - before if v and spread[key].get(v, 0) <= MAX_SPREAD}
    hits = []
    for key, v in sorted(bad):
        sub = df[df[key].astype(str) == v]
        for acc, grp in sub.groupby("account_id", observed=True):
            hits.append({"account_id": acc, "first_event_id": grp.sort_values("ts")["event_id"].iloc[0], "via": f"seed:{key}"})
    return pd.DataFrame(hits, columns=["account_id", "first_event_id", "via"])


def young_thin_components(df, max_accounts=12, since=DAY25, max_events=8):
    G = build_bipartite(df, keys=KEYS, idf=False, min_accounts=2, max_accounts=max_accounts)
    keep = []
    def old_or_thick(node):
        edges = [G[node][acc] for acc in G.neighbors(node)]
        return any(e["first_seen"] < since for e in edges) or sorted(e["n_events"] for e in edges)[len(edges) // 2] > max_events
    for node, data in G.nodes(data=True):
        if data.get("kind") == "account" or old_or_thick(node):
            continue
        accs = list(G.neighbors(node))
        # same person, two accounts: they share something old and thick as well
        shared_old = any(old_or_thick(other) for a in accs for other in G.neighbors(a) if other != node and len(set(G.neighbors(other)) & set(accs)) >= 2)
        if not shared_old:
            keep.append(node)
    H = G.subgraph([n for n, d in G.nodes(data=True) if d.get("kind") == "account"] + keep).copy()
    H.remove_nodes_from([n for n in list(H.nodes) if H.degree(n) == 0])
    P = project_accounts(H)
    comps = component_report(P, top=None)
    # first event of each account on any of its component's identifiers
    first_ev = {}
    for node in keep:
        key = node.split(":", 1)[0]
        val = node.split(":", 1)[1]
        sub = df[df[key].astype(str) == val].sort_values("ts")
        for acc, grp in sub.groupby("account_id", observed=True):
            t = grp["ts"].iloc[0]
            if acc not in first_ev or t < first_ev[acc][0]:
                first_ev[acc] = (t, grp["event_id"].iloc[0])
    return comps, first_ev


def split_abuse_from_takeover(df, accounts):
    """An account whose life in the log *starts* with account_created had no owner to take
    over: that is a fake-account cluster, reported but not submitted."""
    first_type = df.sort_values("ts").groupby("account_id", observed=True)["event_type"].first()
    born = {a for a in accounts if str(first_type.get(a)) == "account_created"}
    return [a for a in accounts if a not in born], sorted(born)


def run(df, prev):
    df = first_seen(df)
    seeds = prev.copy()
    exp = seed_expansion(df, seeds)
    comps, first_ev = young_thin_components(df)
    comp_accounts = [a for accs in comps["accounts"] for a in accs]
    takeover, abuse = split_abuse_from_takeover(df, comp_accounts)
    print(f"seed expansion: {exp['account_id'].nunique()} accounts via {exp['via'].nunique()} identifier kinds")
    print(f"young, thin components: {len(comps)} components, {len(comp_accounts)} accounts; {len(abuse)} look like a fake-account cluster (no history before the shared id), kept out")
    with pd.option_context("display.width", 200, "display.max_colwidth", 60):
        print(comps.assign(accounts=comps["accounts"].apply(lambda x: ", ".join(x[:4]) + (" ..." if len(x) > 4 else ""))).head(12).to_string(index=False))
    rows = []
    for r in prev.itertuples(index=False):
        rows.append({"account_id": r.account_id, "first_event_id": r.first_event_id, "score": 3.0})
    for r in exp.itertuples(index=False):
        rows.append({"account_id": r.account_id, "first_event_id": r.first_event_id, "score": 2.0})
    for a in takeover:
        rows.append({"account_id": a, "first_event_id": first_ev.get(a, (None, None))[1], "score": 1.0})
    out = pd.DataFrame(rows).sort_values("score", ascending=False).drop_duplicates("account_id")
    return out, abuse


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--prev", default=os.path.join(HERE, "checkpoints", "suspects_r1.csv"))
    ap.add_argument("--out", default=os.path.join(HERE, "checkpoints", "suspects_r2.csv"))
    ap.add_argument("--no-score", action="store_true")
    args = ap.parse_args()
    prev = pd.read_csv(args.prev)
    df = dedupe(load_events())
    out, abuse = run(df, prev)
    save_suspects(out[["account_id"]], args.out, scores=out["score"], first_event=out["first_event_id"])
    if not args.no_score:
        score_now(args.out, "--prev", args.prev)


if __name__ == "__main__":
    main()
