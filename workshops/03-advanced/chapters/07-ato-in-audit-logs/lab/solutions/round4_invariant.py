"""
Round 4 reference: the account that was the attacker's before it was the victim's.

Campaign D (pre-hijack) is not an anomaly and it is not shared infrastructure.
The attacker signs up with the victim's email address, never verifies it, logs in
once or twice, and waits. Ten to thirty days later the real person finds the
account "already exists", resets the password from their own device, verifies the
email, adds a card. The attacker's remember-me session survives all of it, and
days later resumes and orders with the victim's new card. Nothing about the
attacker's first login is unusual (the account is new; everything is new), and
the owner's reset looks like any other forgetful owner's.

What is wrong is a sequence. The textbook version of the invariant is "a password
reset must end every other session". Do not write that rule here: in this store
the legitimate flows never emit `sessions_revoked_all` after a reset (857 accounts
complete one; 36 have a revoke of any kind), so the textbook rule flags ~820
innocent owners. Revocation is not logged by the flows you are auditing, which is
itself a finding for the product team. The usable invariant is built from what the
log does record:

  P1  a user-initiated `password_reset_completed` on an account whose
      `account_created` is inside the window, with NO `email_verified` before the
      reset, performed from a device other than the one that created the account.
      A real owner's email is verified at sign-up (the verification link is how
      the account exists at all); here the owner "verifies" only after the reset.
      The attacker could not, because the mail went to the victim.

  P2  (kept for the exercise, never submitted alone) the same reset followed by a
      `session_resume` on a device the account used before the reset. It is the
      *symptom* of the missing revocation, and it fires on every owner whose
      browser rolls a remember-me cookie after a reset: `--p2` prints how many.

No `n_prior` clause, deliberately. Tier D accounts are new: they have almost no
history by construction, which is the opposite lesson from Round 1's left-censoring
guard. A known-history clause here would delete the whole tier.

Time to detect is poor by construction: the first compromise event is the
attacker's login, days to weeks before the owner shows up and the invariant can
fire. `first_event_id` is the first `session_resume` on the creating device after
the reset (the surviving session), which is the earliest event a detector that
waits for the invariant could point at. The scorer will say so.

Run:
    python solutions/round4_invariant.py          # needs solutions/checkpoints/suspects_r3.csv
    python solutions/round4_invariant.py --p2     # P2 alone: how many it flags, and why it is not a rule
"""

import argparse
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
LAB = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(LAB, "tools"))

import pandas as pd  # noqa: E402
from atolab import dedupe, load_events, save_suspects, score_now  # noqa: E402


def creation_facts(df):
    """For every account born inside the window: when, and on which device."""
    c = df[df["event_type"] == "account_created"].sort_values(["ts", "event_id"]).drop_duplicates("account_id")
    return c[["account_id", "ts", "device_id"]].rename(columns={"ts": "created_ts", "device_id": "created_device"})


def rule_p1(df):
    """User resets on window-born accounts, no email_verified before the reset, from another device."""
    created = creation_facts(df)
    resets = df[(df["event_type"] == "password_reset_completed") & (df["actor"] == "user")][["account_id", "ts", "device_id", "event_id"]]
    verified = df[df["event_type"] == "email_verified"].groupby("account_id", observed=True)["ts"].min().rename("verified_ts")
    m = resets.merge(created, on="account_id").merge(verified, on="account_id", how="left")
    unverified = m["verified_ts"].isna() | (m["verified_ts"] > m["ts"])
    other_device = m["device_id"] != m["created_device"]
    hits = m[unverified & other_device].sort_values("ts").drop_duplicates("account_id")
    return hits.rename(columns={"event_id": "reset_event_id", "ts": "reset_ts", "device_id": "reset_device"})


def surviving_session(df, hits):
    """The first session_resume on the creating device after the reset: the attacker coming back."""
    sr = df[(df["event_type"] == "login_success") & (df["auth_method"] == "session_resume")][["account_id", "ts", "device_id", "event_id"]]
    j = hits.merge(sr, on="account_id")
    j = j[(j["ts"] > j["reset_ts"]) & (j["device_id"] == j["created_device"])].sort_values("ts").drop_duplicates("account_id")
    return j.set_index("account_id")["event_id"]


def rule_p2(df):
    """Reset, then a session_resume on a device the account used before the reset. Noisy on purpose."""
    resets = df[(df["event_type"] == "password_reset_completed") & (df["actor"] == "user")].sort_values("ts").drop_duplicates("account_id")[["account_id", "ts"]]
    resets = resets.rename(columns={"ts": "reset_ts"})
    logins = df[df["event_type"] == "login_success"][["account_id", "ts", "device_id", "auth_method"]].merge(resets, on="account_id")
    pre = logins[logins["ts"] < logins["reset_ts"]].groupby("account_id", observed=True)["device_id"].agg(lambda s: set(s.dropna())).rename("pre_devices")
    post = logins[(logins["ts"] > logins["reset_ts"]) & (logins["auth_method"] == "session_resume")].merge(pre, on="account_id")
    post = post[[d in p for d, p in zip(post["device_id"], post["pre_devices"])]]
    return sorted(post["account_id"].unique())


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--prev", default=os.path.join(HERE, "checkpoints", "suspects_r3.csv"))
    ap.add_argument("--out", default=os.path.join(HERE, "checkpoints", "suspects_r4.csv"))
    ap.add_argument("--p2", action="store_true", help="show rule P2 alone (not submitted)")
    ap.add_argument("--no-score", action="store_true")
    args = ap.parse_args()
    df = dedupe(load_events())
    if args.p2:
        p2 = rule_p2(df)
        print(f"P2 alone (reset, then a session_resume on a pre-reset device): {len(p2)} accounts. Not submitted. Score it: python tools/score.py solutions/checkpoints/p2_alone.csv")
        os.makedirs(os.path.join(HERE, "checkpoints"), exist_ok=True)
        pd.DataFrame({"account_id": p2}).to_csv(os.path.join(HERE, "checkpoints", "p2_alone.csv"), index=False)
        return
    prev = pd.read_csv(args.prev)
    hits = rule_p1(df)
    first = surviving_session(df, hits)
    hits = hits.assign(first_event_id=hits["account_id"].map(first).fillna(hits["reset_event_id"]))
    print(f"P1: {len(hits)} accounts (reset with no verified email, from a new device, on a window-born account); {(~hits['account_id'].isin(prev['account_id'])).sum()} not already in Round 3")
    new = pd.DataFrame({"account_id": hits["account_id"], "score": 1.0, "first_event_id": hits["first_event_id"]})
    out = pd.concat([new, prev[["account_id", "score", "first_event_id"]]]).drop_duplicates("account_id")   # D rows win: they carry the first_event_id claim
    save_suspects(out[["account_id"]], args.out, scores=out["score"], first_event=out["first_event_id"])
    if not args.no_score:
        score_now(args.out, "--prev", args.prev)


if __name__ == "__main__":
    main()
