"""
Round 5 reference: the ones that got away, found one session at a time.

By Round 3 a handful of phishing-kit victims and most of the low-and-slow victims
are still unflagged. They have one thing in common that no earlier round looked
at: the operator monetizes. A session on a browser this account has only just
started using adds an address and orders to it. Nothing links the victims to each
other (the kit rotates its cookie, the low-and-slow operator uses a new browser per
victim), and the joint deviation was too weak for the Round 3 model. But the
sequence inside one session is a fingerprint:

    a user session on a *young* device (first seen on this account in the last
    14 days)  +  address_added  +  order_placed with ship_to_new_address
    on an account with at least MIN_HISTORY earlier events.

Why "young" and not "never seen": the kit often spends its first session on a
new cookie only reading the stored cards, and orders from the same cookie a few
days later. Insisting that the device is brand new at the order session misses
those victims; a 14-day window keeps them. The cost is that a few honest
cohorts qualify (gift buyers, new-phone upgraders, privacy browsers whose
cookies are cleared, relocators); the queue is ranked so that they sit lower.

Ranking: the order's amount against this account's own earlier median order (a
phishing kit orders at 1.6x, a low-and-slow operator at 2.5x; a gift buyer's
December order is a normal order that happens to ship elsewhere), plus a bonus
when the session's network is new to the account. The deliverable is the top 100
accounts not already in Round 4's cumulative file, judged on its delta.

MIN_HISTORY is the left-censoring trade from Round 1, paid again with different
numbers. The attacked accounts are thin (the kit picks accounts with only a few
events in the first weeks), so the history clause that was free in Round 1 now
costs recall. Measured on this log, the same rule at 10 / 5 / 3 earlier events
(run with --min-history): 10 loses two of the five missed kit victims, 5 reaches
all five, 3 reaches the same five plus one more thin low-and-slow victim and one more
innocent account, so delta precision does not move. 5 is the reference.

The log has a start date for devices too: a device "first seen" in the log's first
two weeks may be years old. Sessions in the first YOUNG_DAYS of the log are not
judged for this reason.

Run:
    python solutions/round5_session_queue.py                  # needs solutions/checkpoints/suspects_r4.csv
    python solutions/round5_session_queue.py --min-history 10 # the Round 1 setting, for contrast
    python solutions/round5_session_queue.py --min-history 3
"""

import argparse
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
LAB = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(LAB, "tools"))

import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402
from atolab import dedupe, first_seen, load_events, save_suspects, score_now  # noqa: E402

MIN_HISTORY = 5
YOUNG_DAYS = 14


def build_sessions(df):
    """One row per user session: when it started, how much history the account had,
    how old its device was, whether its network was new, and what it did."""
    df = first_seen(df)
    df["n_prior"] = df.groupby("account_id", observed=True).cumcount()
    u = df[df["actor"] == "user"].copy()
    u["amount"] = pd.to_numeric(u["d_amount"], errors="coerce")
    # how long this account had known the device by the time of each event
    dev_first = u.groupby(["account_id", "device_id"], observed=True)["ts"].min().rename("dev_first").reset_index()
    u = u.merge(dev_first, on=["account_id", "device_id"], how="left")
    u["dev_age_days"] = (u["ts"] - u["dev_first"]).dt.total_seconds() / 86400
    u = u.sort_values(["ts", "event_id"])
    g = u.groupby(["account_id", "session_id"], observed=True)
    S = g.agg(start=("ts", "first"), first_event_id=("event_id", "first"), n_prior=("n_prior", "first"), dev_age_days=("dev_age_days", "first"), new_asn=("is_new_asn", "first"),
              has_login=("event_type", lambda s: (s == "login_success").any()), has_address=("event_type", lambda s: (s == "address_added").any())).reset_index()
    orders = u[(u["event_type"] == "order_placed") & (u["d_ship_to_new_address"] == True)]  # noqa: E712
    new_addr = orders.groupby(["account_id", "session_id"], observed=True)["amount"].max().rename("amount").reset_index()
    return S.merge(new_addr, on=["account_id", "session_id"]), u


def prior_median(u):
    """Each order's account median over *earlier* orders only (no lookahead); None if the account has none."""
    o = u[u["event_type"] == "order_placed"].sort_values(["account_id", "ts"])
    # the order being scored must not be in its own baseline
    o["prior_median"] = o.groupby("account_id", observed=True)["amount"].transform(lambda s: s.shift().expanding().median())
    return o[["account_id", "session_id", "prior_median"]].drop_duplicates(["account_id", "session_id"], keep="last")


def candidates(df, min_history=MIN_HISTORY, young_days=YOUNG_DAYS):
    S, u = build_sessions(df)
    day0 = df["ts"].min().normalize()
    pop_median = float(u.loc[u["event_type"] == "order_placed", "amount"].median())
    S = S.merge(prior_median(u), on=["account_id", "session_id"], how="left")
    S["baseline"] = S["prior_median"].fillna(pop_median)
    keep = (S["has_login"] & S["has_address"] & (S["n_prior"] >= min_history) & (S["dev_age_days"] <= young_days) & (S["start"] >= day0 + pd.Timedelta(days=young_days)))
    C = S[keep].copy()
    C["ratio"] = C["amount"] / C["baseline"]
    C["score"] = np.log1p(C["ratio"].clip(upper=20)) + 0.5 * C["new_asn"].astype(float)
    return C.sort_values("score", ascending=False)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--prev", default=os.path.join(HERE, "checkpoints", "suspects_r4.csv"))
    ap.add_argument("--out", default=os.path.join(HERE, "checkpoints", "suspects_r5.csv"))
    ap.add_argument("--top", type=int, default=100)
    ap.add_argument("--min-history", type=int, default=MIN_HISTORY)
    ap.add_argument("--no-score", action="store_true")
    args = ap.parse_args()
    prev = pd.read_csv(args.prev)
    df = dedupe(load_events())
    C = candidates(df, min_history=args.min_history)
    best = C.drop_duplicates("account_id")
    fresh = best[~best["account_id"].isin(prev["account_id"])].head(args.top)
    print(f"{len(C)} candidate sessions on {best['account_id'].nunique()} accounts (min history {args.min_history}, device <= {YOUNG_DAYS} days old); {len(fresh)} not already flagged -> queue")
    # new rows are squashed below the earlier rounds' scores so the cumulative ranking still reads strongest-first
    s = fresh["score"].to_numpy()
    new = pd.DataFrame({"account_id": fresh["account_id"].to_numpy(), "score": 0.5 * s / (1.0 + s), "first_event_id": fresh["first_event_id"].to_numpy()})
    out = pd.concat([prev[["account_id", "score", "first_event_id"]], new]).drop_duplicates("account_id")
    save_suspects(out[["account_id"]], args.out, scores=out["score"], first_event=out["first_event_id"])
    if not args.no_score:
        score_now(args.out, "--prev", args.prev)


if __name__ == "__main__":
    main()
